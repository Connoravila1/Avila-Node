//! The connection manager — `CConnman`/`PeerManager`'s smallest honest
//! core: a bounded set of [`PeerSession`]s, each with its own
//! [`PeerSync`], all driven by one [`PeerManager::tick`] call.
//!
//! Single-threaded round-robin: `tick` polls every session (nonblocking),
//! feeds events into the shared [`Chainstate`], sends whatever the sync
//! layer asks for, evicts stalled/misbehaving peers, and reports
//! [`NetEvent`]s the caller can log or budget.
//!
//! Generic over the stream type so tests run entirely on in-memory pipes —
//! `PeerManager<End>` needs no sockets, while the concrete
//! `PeerManager<TcpStream>` gets `connect()`/`listen()`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::BlockHash;

use crate::addrman::{self, AddrBook};
use crate::message::{AddrV2Entry, Message, NODE_P2P_V2, NetAddr, Version};
use crate::session::{
    HANDSHAKE_TIMEOUT, PeerInfo, PeerSession, SessionError, SessionEvent, build_version, wall_epoch,
};
use crate::sync::{MAX_BLOCKS_IN_TRANSIT_PER_PEER, PeerSync};

/// Maximum simultaneous peers — small by design; more arrive when
/// connection scheduling matures.
pub const DEFAULT_MAX_PEERS: usize = 8;

/// Global bound on outstanding block reservations across the whole peer
/// set — independent of peer count, so aggregate download memory stays
/// predictable (Core bounds this through `BLOCK_DOWNLOAD_WINDOW`).
pub const MAX_BLOCKS_IN_TRANSIT_TOTAL: usize = 1024;

/// Seconds between initiated BIP330 reconciliation rounds per link —
/// BIP-330 paces ~1/s per link on mainnet-scale pools; we start
/// conservative (a round is cheap — one sketch each way).
const RECON_INTERVAL: Duration = Duration::from_secs(4);

/// Delay before the first round on a new link — early `mempool`/`inv`
/// traffic settles first so the sketch sees a fuller picture.
const RECON_FIRST_DELAY: Duration = Duration::from_secs(10);

/// The pool's salted short-ids plus the reverse map — `short_id` keys
/// this link's sketch; the map resolves `reconcildiff` asks back to
/// bodies.
fn recon_pool(
    mempool: &avila_mempool::Mempool,
    salt: u64,
) -> (Vec<u32>, std::collections::HashMap<u32, avila_consensus::hash::Txid>) {
    let mut ids = Vec::new();
    let mut map = std::collections::HashMap::new();
    for txid in mempool.txids() {
        let id = crate::recon::short_id(salt, txid.as_bytes());
        ids.push(id);
        map.insert(id, txid);
    }
    (ids, map)
}

/// Peers that delivered useful headers or blocks within this window are
/// protected from inbound eviction (Core protects for ~30 min; our
/// window is shorter since sessions are lighter).
pub const USEFUL_PROTECTION_WINDOW: Duration = Duration::from_secs(20 * 60);

/// Per-peer send-buffer cap — Core's ~4 MiB `MAX_SEND_BUFFER` analogue,
/// sized generously for a headers burst.
pub const SEND_BUDGET_PER_PEER: usize = 8 << 20;

/// How often a peer must show activity before we consider it idle — for
/// stall detection the sync layer's per-request timeout applies; this is
/// the connection-level liveness floor (Core pings at 2-minute intervals).
pub const PING_INTERVAL: Duration = Duration::from_secs(120);

/// What one peer's removal meant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The session reported a terminal condition.
    Session(String),
    /// The sync layer proved misbehavior (bad headers/blocks).
    Misbehavior(String),
    /// The peer stopped answering block requests (stall timeout).
    Stalled,
}

/// An event the caller should observe.
#[derive(Clone, Debug)]
pub enum NetEvent {
    /// A peer completed the handshake.
    Connected {
        /// The manager-assigned peer id.
        peer: u64,
        /// What the peer announced in `version`.
        info: Box<PeerInfo>,
    },
    /// A peer was dropped, with the reason.
    Disconnected {
        /// The peer id.
        peer: u64,
        /// Why it left.
        reason: DisconnectReason,
    },
    /// Our connected tip advanced — `(new height)`.
    TipAdvanced(u32),
    /// A peer announced blocks we don't have (headers may need fetching).
    Announced {
        /// The peer id.
        peer: u64,
        /// Announced block hashes we lack.
        missing: Vec<BlockHash>,
    },
}

struct PeerEntry<S> {
    session: PeerSession<S>,
    sync: PeerSync,
    /// The peer's network address when we know it (outbound dials do).
    remote: Option<NetAddr>,
    /// The peer sent `sendheaders` — announce new tips via `headers`,
    /// not `inv` (Core's `fSendheaders` preference).
    wants_headers_announce: bool,
    /// Inbound connection (they dialed us). Core only ever evicts
    /// inbound peers — outbound slots are ours to manage.
    inbound: bool,
    /// When this peer was registered.
    connected_at: Instant,
    /// Last time the peer gave us something useful — headers we
    /// accepted or a block body. Core's `m_most_recent_block_time` /
    /// header/tx protection analog for eviction scoring.
    last_useful: Instant,
    /// Time of the last received message of any kind.
    last_rx: Instant,
    /// Outstanding handshake deadline check cadence.
    last_ping: Instant,
    /// The ping we last sent and haven't seen a pong for.
    ping_outstanding: Option<(u64, Instant)>,
    /// Last measured round-trip (`getpeerinfo` `pingtime`).
    ping_last: Option<Duration>,
    /// Smallest round-trip ever seen (`minping`).
    ping_min: Option<Duration>,
    /// Node-clock epoch of the last block this peer delivered
    /// (`last_block_time`).
    last_block_time: Option<i64>,
    /// Node-clock epoch of the last tx this peer delivered
    /// (`last_transaction`).
    last_tx_time: Option<i64>,
    /// Node-clock epoch of the last inv/headers announcement
    /// (`lastannounce`).
    last_announce: Option<i64>,
    /// Height of the last header this peer fed us that we indexed
    /// (`synced_headers`); -1 when none.
    synced_header_height: i64,
    /// Height of the last block from this peer that connected
    /// (`synced_blocks`); -1 when none.
    synced_block_height: i64,
    /// Address entries accepted from this peer (`addr_processed`).
    addr_processed: u64,
    /// Address entries dropped by the rate limiter
    /// (`addr_rate_limited`) — zero until a limiter exists.
    addr_rate_limited: u64,
    /// BIP330 link state — `Some` when the peer negotiated `sendrecon`.
    recon: Option<crate::recon::ReconPeer>,
    /// An open reconciliation round we initiated (awaiting `sketch`).
    recon_round: Option<crate::recon::ReconRound>,
    /// Our pool's short-id -> txid map for the last open/answer — how a
    /// `reconcildiff` ask resolves to a body we can send.
    recon_map: std::collections::HashMap<u32, avila_consensus::hash::Txid>,
    /// When the next initiated round may start.
    next_recon: Instant,
    /// An in-progress bisected close: our half-pools and the misses
    /// collected so far — `lo` is consumed by the first `sketch`, `hi`
    /// by the second (fixed reply order).
    recon_bisect: Option<ReconBisect>,
}

/// Pending bisected-round state — see [`crate::recon::bisect`].
struct ReconBisect {
    /// Our pool's lo half (bit 31 clear).
    lo: Vec<u32>,
    /// Our pool's hi half (bit 31 set).
    hi: Vec<u32>,
    /// Whether the lo-half sketch was already decoded.
    got_lo: bool,
    /// Misses accumulated across both halves.
    misses: Vec<u32>,
}

/// A read-only view of one connected peer — the manager's state is
/// private, so status displays pull this snapshot per tick.
#[derive(Clone, Debug)]
pub struct PeerSnapshot {
    /// The manager-assigned peer id.
    pub id: u64,
    /// Remote address when known (always known for outbound dials).
    pub remote: Option<std::net::SocketAddr>,
    /// Inbound — they dialed us.
    pub inbound: bool,
    /// The version/verack handshake completed.
    pub established: bool,
    /// Their claimed best height from `version`, if the handshake ran.
    pub start_height: Option<i32>,
    /// Their user agent, if the handshake ran.
    pub user_agent: Option<String>,
    /// Their protocol version, if the handshake ran.
    pub version: Option<i32>,
    /// Services they offer, if the handshake ran.
    pub services: Option<u64>,
    /// Whether they want transaction relay, if the handshake ran.
    pub relay: Option<bool>,
    /// Prefers `headers` announcements over `inv`.
    pub wants_headers_announce: bool,
    /// Headers we've applied that this peer sent.
    pub headers_received: usize,
    /// Block bodies this peer has sent.
    pub blocks_received: usize,
    /// Outstanding `getdata` requests to this peer.
    pub in_flight: usize,
    /// Seconds since the connection registered.
    pub connected_secs: u64,
    /// Seconds since this peer last gave us something useful.
    pub idle_secs: u64,
    /// Wire counters and wall-clock times (`conntime`, `lastsend`,
    /// `lastrecv`, byte and per-command totals, `session_id`).
    pub telemetry: crate::session::SessionTelemetry,
    /// Last ping round-trip in seconds (`pingtime`), if measured.
    pub ping_last_secs: Option<f64>,
    /// Smallest round-trip seen (`minping`).
    pub ping_min_secs: Option<f64>,
    /// Seconds an unanswered ping has been outstanding (`pingwait`).
    pub ping_wait_secs: Option<f64>,
    /// Last block this peer delivered, epoch seconds; -1 if none.
    pub last_block_time: i64,
    /// Last tx this peer delivered, epoch seconds; -1 if none.
    pub last_tx_time: i64,
    /// Last inv/headers announcement, epoch seconds; -1 if none.
    pub last_announce: i64,
    /// Height of the last header we indexed from this peer; -1 if none.
    pub synced_header_height: i64,
    /// Height of the last peer-delivered block that connected; -1 if none.
    pub synced_block_height: i64,
    /// Addresses accepted from this peer.
    pub addr_processed: u64,
    /// Addresses rate-limited from this peer.
    pub addr_rate_limited: u64,
    /// Outstanding `getdata` block hashes (for `inflight` heights).
    pub in_flight_hashes: Vec<BlockHash>,
    /// `transport_protocol_type` — "v1"/"v2" (Core also has
    /// "detecting" mid-handshake; our sessions resolve first).
    pub transport_protocol: &'static str,
    /// `session_id` — the BIP324 session id, `None` on v1 like Core's
    /// empty string.
    pub v2_session_id: Option<[u8; 32]>,
    /// BIP330 reconciliation negotiated on this link.
    pub recon: bool,
}

/// A bounded set of peers sharing one [`Chainstate`].
pub struct PeerManager<S> {
    peers: HashMap<u64, PeerEntry<S>>,
    next_id: u64,
    max_peers: usize,
    /// The peer currently paging `getheaders` — only it continues pages;
    /// others get one locator to learn their view. Core's sync-peer
    /// discipline: N parallel header downloads fetch the same ranges.
    headers_leader: Option<u64>,
    /// Aggregate bound on block reservations across all peers —
    /// defaults to [`MAX_BLOCKS_IN_TRANSIT_TOTAL`].
    max_in_flight_total: usize,
    /// Height-sorted `(height, hash)` fetch index for the fill pass —
    /// rebuilt only when the header set grows, so each tick scans the
    /// unfetched suffix instead of re-sorting the whole index per peer.
    fetch_index: Vec<(u32, avila_consensus::hash::BlockHash)>,
    /// Header count `fetch_index` was built at.
    fetch_index_headers: usize,
    /// Gossiped peer addresses — discovery lives here.
    addrbook: AddrBook,
    /// The transaction pool — policy layer owned here so `tx` intake,
    /// `inv` relay, and block-connect reconciliation stay atomic with
    /// the tick loop.
    mempool: avila_mempool::Mempool,
    /// Wire bytes absorbed from sessions that have already ended —
    /// `getnettotals` is cumulative over all sessions since startup
    /// (Core's `CConnman::nTotalBytesSent`/`nTotalBytesRecv`), so a
    /// disconnected peer's traffic must not vanish with its entry.
    closed_bytes_sent: u64,
    closed_bytes_recv: u64,
    /// The operator's `addnode` list — Core's `connman.m_added_nodes`
    /// (`node` string, `use_v2transport`). Entries are deduplicated by
    /// the node string and dialed by [`PeerManager::tick_net`].
    added_nodes: Vec<(String, bool)>,
    /// `setnetworkactive` — when false every session is dropped and no
    /// outbound dialing happens (`tick_net`/`maintain_outbounds`).
    network_active: bool,
    /// Last dial time per `added_nodes` entry — the addnode retry
    /// backoff (Core's connman sleeps between addnode connection
    /// rounds; without this every disconnect event would spin-dial
    /// dead entries).
    addnode_dial: HashMap<String, Instant>,
    /// When `maintain_outbounds` last ran — paces the periodic
    /// self-heal dial so a starved peer set doesn't spin.
    last_maintained: Option<Instant>,
    /// The operator ban list — Core's `BanMan`/`m_banned`: consulted
    /// on every dial and (future) inbound accept; `setban add` also
    /// drops matching live peers.
    bans: crate::banman::BanList,
    /// Where `bans` persists — `<net-datadir>/banlist.json`, written on
    /// every mutation like Core's `DumpBanlist`.
    banlist_path: Option<std::path::PathBuf>,
    /// Completed dial attempts — workers send `(addr, session result)`
    /// here and `maintain_outbounds` drains it on the tick, so an
    /// unreachable candidate costs a worker's 5s timeout instead of
    /// blocking the sync loop (Core's `ThreadOpenConnections` runs
    /// dials off the message loop the same way). The session includes
    /// any completed BIP324 handshake.
    dial_tx: std::sync::mpsc::Sender<(SocketAddr, DialOutcome)>,
    dial_rx: std::sync::mpsc::Receiver<(SocketAddr, DialOutcome)>,
    /// Dials in flight — counted against outbound slots so a dead
    /// network can't queue unbounded workers, and deduplicated so the
    /// same address is never dialed twice at once.
    pending_dials: std::collections::HashSet<SocketAddr>,
    /// The epoch-seconds clock every time-domain decision reads —
    /// ban checks, version `timestamp`s, session telemetry and the
    /// `last_*` fields. Core's `GetTime`: [`wall_epoch`] until the
    /// node substitutes its mockable clock via [`Self::set_clock`].
    clock: fn() -> i64,
    /// `-v2transport` — whether outbound dials attempt BIP324 first.
    /// Core defaults to true since v26; `addnode`'s per-node flag
    /// overrides for manual peers.
    v2transport: bool,
    /// Whether we advertise `NODE_COMPACT_FILTERS` (BIP157 serving) —
    /// set when the caller enables `-blockfilterindex`; without it a
    /// `getcf*` request means misbehavior (Core's
    /// `peer.m_our_services & NODE_COMPACT_FILTERS` gate).
    serve_filters: bool,
    /// Accepted sockets whose transport handshake finished — workers
    /// send `(remote addr, session)` here; `drain_inbounds` admits
    /// them on the tick like `maintain_outbounds` drains dials.
    inbound_tx: std::sync::mpsc::Sender<(SocketAddr, DialOutcome)>,
    inbound_rx: std::sync::mpsc::Receiver<(SocketAddr, DialOutcome)>,
    /// Accept-side handshakes in flight — bounds the worker pool a
    /// connect-flood could otherwise grow without limit.
    pending_accepts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    /// The node's task queue — Core's `CScheduler`. Periodic work
    /// (`peers.dat` dumps, expirations) runs here so `mockscheduler`
    /// can fast-forward it on regtest.
    tasks: Vec<ScheduledTask<S>>,
}

/// One recurring scheduler entry — `run_due_tasks` fires `work` when
/// `next_run <= now` on the manager's mockable clock.
pub struct ScheduledTask<S> {
    /// Human label — for logs and future introspection.
    pub name: String,
    /// Seconds between runs.
    pub every_secs: u64,
    /// Next fire time on the manager clock.
    pub next_run: i64,
    /// The job — `&mut PeerManager` so tasks can touch any subsystem.
    pub work: TaskWork<S>,
}

/// A scheduled job body — `&mut PeerManager` so tasks can touch any
/// subsystem.
pub type TaskWork<S> = Box<dyn FnMut(&mut PeerManager<S>) + Send>;

impl<S: Read + Write> PeerManager<S> {
    /// An empty manager — `max_peers` bounds the set.
    #[must_use]
    pub fn new(max_peers: usize) -> Self {
        let dial_channel = std::sync::mpsc::channel();
        let inbound_channel = std::sync::mpsc::channel();
        Self {
            peers: HashMap::new(),
            next_id: 0,
            max_peers,
            headers_leader: None,
            max_in_flight_total: MAX_BLOCKS_IN_TRANSIT_TOTAL,
            fetch_index: Vec::new(),
            fetch_index_headers: usize::MAX,
            addrbook: AddrBook::new(),
            mempool: avila_mempool::Mempool::new(),
            closed_bytes_sent: 0,
            closed_bytes_recv: 0,
            added_nodes: Vec::new(),
            network_active: true,
            addnode_dial: HashMap::new(),
            last_maintained: None,
            bans: crate::banman::BanList::new(),
            banlist_path: None,
            dial_tx: dial_channel.0,
            dial_rx: dial_channel.1,
            pending_dials: std::collections::HashSet::new(),
            inbound_tx: inbound_channel.0,
            inbound_rx: inbound_channel.1,
            pending_accepts: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            serve_filters: false,
            clock: wall_epoch,
            v2transport: true,
            tasks: Vec::new(),
        }
    }

    /// Substitutes the manager's epoch clock — the node passes its
    /// mockable `GetTime` so ban expiry, `version` timestamps and peer
    /// telemetry all honor `setmocktime`. Sessions adopt the current
    /// clock at registration; since the node's clock reads a shared
    /// atomic, a later `setmocktime` still shifts every session.
    pub fn set_clock(&mut self, clock: fn() -> i64) {
        self.clock = clock;
    }

    /// `-v2transport` — Core's `fUseV2Transport`: automatic
    /// outbounds attempt BIP324 when true (the Core default).
    pub fn set_v2transport(&mut self, on: bool) {
        self.v2transport = on;
    }

    /// The configured `-v2transport` default — `addnode` without an
    /// explicit flag resolves against it, like Core's
    /// `connOptions.m_use_v2transport`.
    #[must_use]
    pub fn v2transport(&self) -> bool {
        self.v2transport
    }

    /// `-peerblockfilters`/`blockfilterindex` — advertise
    /// `NODE_COMPACT_FILTERS` in every version we send, so BIP157
    /// requests become legitimate instead of misbehavior.
    pub fn set_serve_filters(&mut self, on: bool) {
        self.serve_filters = on;
    }

    /// Whether `NODE_COMPACT_FILTERS` is being advertised.
    #[must_use]
    pub fn serve_filters(&self) -> bool {
        self.serve_filters
    }

    /// `-maxmempool` — the pool's serialized-byte cap (Core default
    /// 300 MB). Lower values tighten eviction pressure.
    pub fn set_max_mempool_bytes(&mut self, bytes: usize) {
        self.mempool.set_max_bytes(bytes);
    }

    /// Removes a peer, folding its wire counters into the cumulative
    /// totals so `getnettotals` keeps counting past sessions.
    fn drop_peer(&mut self, id: u64) {
        if let Some(p) = self.peers.remove(&id) {
            let t = p.session.telemetry();
            self.closed_bytes_sent = self.closed_bytes_sent.saturating_add(t.bytes_sent);
            self.closed_bytes_recv = self.closed_bytes_recv.saturating_add(t.bytes_recv);
        }
    }

    /// `getnettotals` — cumulative wire bytes since startup: closed
    /// sessions plus every live session's current counters.
    #[must_use]
    pub fn net_totals(&self) -> (u64, u64) {
        self.peers.values().fold(
            (self.closed_bytes_sent, self.closed_bytes_recv),
            |(sent, recv), p| {
                let t = p.session.telemetry();
                (
                    sent.saturating_add(t.bytes_sent),
                    recv.saturating_add(t.bytes_recv),
                )
            },
        )
    }

    /// Live peer count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// A snapshot of every connected peer, for status displays —
    /// ordered by peer id (registration order).
    #[must_use]
    pub fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let mut out: Vec<PeerSnapshot> = self
            .peers
            .iter()
            .map(|(id, peer)| {
                let info = peer.session.peer();
                PeerSnapshot {
                    id: *id,
                    remote: peer.remote.as_ref().map(addrman::socket_addr),
                    inbound: peer.inbound,
                    established: peer.session.established(),
                    start_height: info.map(|i| i.start_height),
                    user_agent: info.map(|i| i.user_agent.clone()),
                    version: info.map(|i| i.version),
                    services: info.map(|i| i.services),
                    relay: info.map(|i| i.relay),
                    wants_headers_announce: peer.wants_headers_announce,
                    headers_received: peer.sync.headers_applied(),
                    blocks_received: peer.sync.blocks_received(),
                    in_flight: peer.sync.in_flight(),
                    connected_secs: peer.connected_at.elapsed().as_secs(),
                    idle_secs: peer.last_useful.elapsed().as_secs(),
                    telemetry: peer.session.telemetry(),
                    ping_last_secs: peer.ping_last.map(|d| d.as_secs_f64()),
                    ping_min_secs: peer.ping_min.map(|d| d.as_secs_f64()),
                    ping_wait_secs: peer
                        .ping_outstanding
                        .map(|(_, t)| t.elapsed().as_secs_f64()),
                    last_block_time: peer.last_block_time.unwrap_or(-1),
                    last_tx_time: peer.last_tx_time.unwrap_or(-1),
                    last_announce: peer.last_announce.unwrap_or(-1),
                    synced_header_height: peer.synced_header_height,
                    synced_block_height: peer.synced_block_height,
                    addr_processed: peer.addr_processed,
                    addr_rate_limited: peer.addr_rate_limited,
                    in_flight_hashes: peer.sync.in_flight_hashes().collect(),
                    transport_protocol: peer.session.transport_protocol(),
                    v2_session_id: peer.session.v2_session_id(),
                    recon: peer.recon.is_some(),
                }
            })
            .collect();
        out.sort_by_key(|p| p.id);
        out
    }

    /// Overrides the aggregate in-flight block budget (testing and
    /// resource-preset knob). Defaults to [`MAX_BLOCKS_IN_TRANSIT_TOTAL`].
    pub fn set_max_in_flight_total(&mut self, n: usize) {
        self.max_in_flight_total = n;
    }

    /// Whether no peers are connected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// The gossiped-address table.
    #[must_use]
    pub fn addr_book(&self) -> &AddrBook {
        &self.addrbook
    }

    /// Whether another outbound peer may be added.
    #[must_use]
    pub fn has_slot(&self) -> bool {
        self.peers.len() < self.max_peers
    }

    /// Registers an outbound session (already constructed, version queued).
    /// Returns the peer id, or `None` if the peer set is full.
    pub fn add_outbound(&mut self, session: PeerSession<S>) -> Option<u64> {
        self.add(session, None, false)
    }

    /// Registers an inbound session. When the set is full the
    /// worst-scoring inbound peer is evicted to make room — Core's
    /// `SelectNodeToEvict` behavior (outbound peers are never evicted
    /// to admit inbound).
    pub fn add_inbound(&mut self, session: PeerSession<S>) -> Option<u64> {
        self.add_inbound_from(session, None)
    }

    /// `add_inbound` carrying the peer's socket address — the
    /// listener knows it; `PeerSession` doesn't retain it.
    pub fn add_inbound_from(
        &mut self,
        session: PeerSession<S>,
        remote: Option<NetAddr>,
    ) -> Option<u64> {
        if !self.has_slot() {
            self.evict_worst_inbound();
        }
        self.add(session, remote, true)
    }

    /// Registers an outbound session with a known remote address.
    pub fn add_outbound_to(&mut self, session: PeerSession<S>, remote: NetAddr) -> Option<u64> {
        self.add(session, Some(remote), false)
    }

    /// Evicts the least valuable inbound peer, if any. Peers that
    /// recently provided useful data, or currently lead the headers
    /// download, are protected first; among the rest the least recently
    /// useful peer leaves (ties: longest connected) — mirroring Core's
    /// `SelectNodeToEvict` protection-then-score ordering.
    fn evict_worst_inbound(&mut self) -> Option<u64> {
        let now = Instant::now();
        let mut scored: Vec<(bool, Instant, Instant, u64)> = self
            .peers
            .iter()
            .filter(|(id, p)| p.inbound && self.headers_leader != Some(**id))
            .map(|(id, p)| {
                let protected = now.duration_since(p.last_useful) < USEFUL_PROTECTION_WINDOW;
                // Reverse-ordered key: unprotected first, then oldest
                // last_useful, then oldest connected_at.
                (protected, p.last_useful, p.connected_at, *id)
            })
            .collect();
        // Unprotected sort before protected; within a class, the least
        // recently useful and longest-connected peer is the target.
        scored.sort();
        let worst = scored
            .iter()
            .find(|(protected, ..)| !protected)
            .or_else(|| scored.first())
            .map(|(.., id)| *id);
        if let Some(id) = worst {
            self.drop_peer(id);
        }
        worst
    }

    fn add(
        &mut self,
        mut session: PeerSession<S>,
        remote: Option<NetAddr>,
        inbound: bool,
    ) -> Option<u64> {
        if !self.has_slot() {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        session.set_clock(self.clock);
        let now = Instant::now();
        self.peers.insert(
            id,
            PeerEntry {
                session,
                sync: PeerSync::new(),
                remote,
                wants_headers_announce: false,
                inbound,
                connected_at: now,
                last_useful: now,
                last_rx: now,
                last_ping: now,
                ping_outstanding: None,
                ping_last: None,
                ping_min: None,
                last_block_time: None,
                last_tx_time: None,
                last_announce: None,
                synced_header_height: -1,
                synced_block_height: -1,
                addr_processed: 0,
                addr_rate_limited: 0,
                recon: None,
                recon_round: None,
                recon_map: std::collections::HashMap::new(),
                next_recon: Instant::now(),
                recon_bisect: None,
            },
        );
        Some(id)
    }

    /// Drives every session once: flush → read → dispatch → reply. Returns
    /// the events a caller should observe; `cs` absorbs headers/blocks.
    pub fn tick(&mut self, cs: &mut Chainstate, now: u32) -> Vec<NetEvent> {
        let mut events = Vec::new();
        let mut dead = Vec::new();
        // Aggregate reservation budget shared by every event this tick —
        // headers-driven and inv-driven fetches draw it down too.
        let mut global_free = self.max_in_flight_total.saturating_sub(self.in_flight());
        let serve_filters = self.serve_filters;
        let Self {
            peers,
            addrbook,
            headers_leader,
            mempool,
            ..
        } = self;
        let mut announce_tip: Option<u64> = None;
        // txid/wtxid to relay at end of tick, and the peer it came from.
        let mut announce_tx: Option<(
            u64,
            avila_consensus::hash::Txid,
            avila_consensus::hash::Wtxid,
        )> = None;
        for (&id, peer) in peers.iter_mut() {
            if let Err(e) = peer.session.check_handshake_timeout() {
                dead.push((id, DisconnectReason::Session(e.to_string())));
                continue;
            }
            match peer.session.poll() {
                Ok(peer_events) => {
                    for event in peer_events {
                        peer.last_rx = Instant::now();
                        Self::dispatch(
                            id,
                            peer,
                            event,
                            cs,
                            now,
                            addrbook,
                            headers_leader,
                            &mut announce_tip,
                            &mut announce_tx,
                            mempool,
                            &mut global_free,
                            &mut events,
                            &mut dead,
                            serve_filters,
                        );
                    }
                }
                Err(e) => dead.push((id, DisconnectReason::Session(e.to_string()))),
            }
            // Periodic liveness ping.
            if peer.session.established() && peer.last_ping.elapsed() > PING_INTERVAL {
                let nonce = peer.last_rx.elapsed().subsec_nanos().into(); // arbitrary
                if peer.session.send(&Message::Ping(nonce)).is_ok() {
                    peer.last_ping = Instant::now();
                    peer.ping_outstanding = Some((nonce, Instant::now()));
                }
            }
            // Stall eviction.
            if peer.sync.stalled() {
                dead.push((id, DisconnectReason::Stalled));
            }
        }
        for (id, reason) in dead {
            self.drop_peer(id);
            if self.headers_leader == Some(id) {
                self.headers_leader = None;
            }
            events.push(NetEvent::Disconnected { peer: id, reason });
        }
        // Announce a newly connected tip to every established peer except
        // the one that delivered it (Core's `NewPoWValidBlock` relay).
        if announce_tip.is_some() {
            self.send_tip_announce(cs, announce_tip);
        }
        // Relay an accepted tx: wtxid inv for wtxidrelay peers, txid
        // otherwise (Core's BIP339 split); the source peer is excluded.
        if let Some((source, txid, wtxid)) = announce_tx {
            self.send_tx_inv(Some(source), &txid, &wtxid);
        }
        self.fill_queues(cs);
        self.recon_pass();
        events
    }

    /// BIP330 scheduled rounds: for every established link that
    /// negotiated `sendrecon` and is due, open a sketch round over the
    /// current pool. Failed/finished rounds clear on the next due tick.
    fn recon_pass(&mut self) {
        let now = Instant::now();
        for peer in self.peers.values_mut() {
            let Some(link) = peer.recon else {
                continue;
            };
            if !link.they_respond
                || !peer.session.established()
                || now < peer.next_recon
            {
                continue;
            }
            peer.next_recon = now + RECON_INTERVAL;
            let salt = link.our_salt ^ link.their_salt;
            let (our_ids, our_map) = recon_pool(&self.mempool, salt);
            let capacity = (our_ids.len() / 64).clamp(8, 512);
            let (round, req) = crate::recon::ReconRound::open(&our_ids, capacity);
            peer.recon_round = Some(round);
            peer.recon_map = our_map;
            let _ = peer.session.send(&req);
        }
    }

    /// Sends a tx inventory announcement to every established peer that
    /// accepts tx relay (BIP339: `wtx` for wtxidrelay peers, `tx`
    /// otherwise). `exclude` spares the peer that supplied the tx —
    /// `None` for locally submitted transactions.
    fn send_tx_inv(
        &mut self,
        exclude: Option<u64>,
        txid: &avila_consensus::hash::Txid,
        wtxid: &avila_consensus::hash::Wtxid,
    ) {
        for (&id, peer) in &mut self.peers {
            if Some(id) == exclude || !peer.session.established() {
                continue;
            }
            let wants_tx = peer.session.peer().is_some_and(|i| i.relay);
            if !wants_tx {
                continue;
            }
            let (inv_type, hash) = if peer.session.peer().is_some_and(|i| i.wtxid_relay) {
                (
                    crate::message::InvType::Wtx,
                    BlockHash::from_bytes(*wtxid.as_bytes()),
                )
            } else {
                (
                    crate::message::InvType::Tx,
                    BlockHash::from_bytes(*txid.as_bytes()),
                )
            };
            let _ = peer
                .session
                .send(&Message::Inv(vec![crate::message::InvVector {
                    inv_type,
                    hash,
                }]));
        }
    }

    /// Registers a periodic task — Core's `CScheduler::scheduleEvery`.
    /// `work` runs each `every_secs` on the manager clock.
    pub fn schedule_every(
        &mut self,
        name: &str,
        every_secs: u64,
        work: impl FnMut(&mut PeerManager<S>) + Send + 'static,
    ) {
        self.tasks.push(ScheduledTask {
            name: name.to_string(),
            every_secs,
            next_run: (self.clock)() + every_secs as i64,
            work: Box::new(work),
        });
    }

    /// Runs every due task once — the sync loop calls this per tick.
    /// `mem::take` frees the borrow so `work` can mutate the manager.
    pub fn run_due_tasks(&mut self) {
        let now = (self.clock)();
        if self.tasks.iter().all(|t| t.next_run > now) {
            return;
        }
        let mut tasks = std::mem::take(&mut self.tasks);
        for t in &mut tasks {
            if t.next_run <= now {
                (t.work)(self);
                t.next_run = now + t.every_secs as i64;
            }
        }
        self.tasks = tasks;
    }

    /// `mockscheduler` — advances every task's clock by `secs` and runs
    /// whatever falls due, like Core's `MockForward`. Each task runs at
    /// most once regardless of how many intervals the delta spans.
    pub fn scheduler_forward(&mut self, secs: u64) {
        for t in &mut self.tasks {
            t.next_run -= secs as i64;
        }
        self.run_due_tasks();
    }

    /// Fetch specific blocks by hash — the rescan reacquisition path.
    /// Picks the first established peer that advertises full/limited
    /// block service; returns true when a request went out.
    pub fn request_blocks(&mut self, hashes: &[avila_consensus::hash::BlockHash]) -> bool {
        let invs: Vec<crate::message::InvVector> = hashes
            .iter()
            .map(|hash| crate::message::InvVector {
                inv_type: crate::message::InvType::WitnessBlock,
                hash: *hash,
            })
            .collect();
        if invs.is_empty() {
            return false;
        }
        let msg = Message::GetData(invs);
        for peer in self.peers.values_mut() {
            if !peer.session.established() {
                continue;
            }
            let services = peer.session.peer().map(|p| p.services).unwrap_or_default();
            if services & (crate::message::NODE_NETWORK | crate::message::NODE_NETWORK_LIMITED) == 0
            {
                continue;
            }
            if peer.session.send(&msg).is_ok() {
                return true;
            }
        }
        false
    }

    /// Announces a locally submitted transaction to every relay-accepting
    /// peer — the broadcast half of `sendrawtransaction`.
    pub fn announce_tx(
        &mut self,
        txid: avila_consensus::hash::Txid,
        wtxid: avila_consensus::hash::Wtxid,
    ) {
        self.send_tx_inv(None, &txid, &wtxid);
    }

    /// Announces the connected tip to every established peer — `headers`
    /// for sendheaders peers, `inv` otherwise (Core's `NewPoWValidBlock`
    /// fan-out). `exclude` spares the peer that delivered the block;
    /// `None` for locally submitted/mined blocks.
    fn send_tip_announce(&mut self, cs: &Chainstate, exclude: Option<u64>) {
        // The connected tip — not `tree().tip()`, which is the best
        // *header* and may sit above the connected chain.
        let tip_hash = cs.chain().last().copied();
        let tip_header = tip_hash.and_then(|h| cs.tree().get(&h)).map(|n| n.header);
        for (&id, peer) in &mut self.peers {
            if Some(id) == exclude || !peer.session.established() {
                continue;
            }
            let msg = if peer.wants_headers_announce {
                match tip_header {
                    Some(header) => Message::Headers(vec![header]),
                    None => continue,
                }
            } else {
                match tip_hash {
                    Some(hash) => Message::Inv(vec![crate::message::InvVector {
                        inv_type: crate::message::InvType::Block,
                        hash,
                    }]),
                    None => continue,
                }
            };
            let _ = peer.session.send(&msg);
        }
    }

    /// Announces a locally submitted or mined tip to every peer — the
    /// relay half of `submitblock`.
    pub fn announce_tip(&mut self, cs: &Chainstate) {
        self.send_tip_announce(cs, None);
    }

    /// The download scheduler: every tick, each established peer gets a
    /// `getdata` for indexed-but-unfetched blocks no peer has reserved.
    /// Peers that stall or leave simply stop holding reservations, so an
    /// interrupted download resumes through this pass automatically.
    fn fill_queues(&mut self, cs: &Chainstate) {
        // Leaderless and connected: the first established peer resumes
        // headers paging from our tip (locator-based, so cheap).
        if self.headers_leader.is_none()
            && let Some((&id, peer)) = self.peers.iter_mut().find(|(_, p)| p.session.established())
        {
            self.headers_leader = Some(id);
            let req = peer.sync.request_headers(cs);
            let _ = peer.session.send(&req);
        }
        let mut reserved: std::collections::HashSet<BlockHash> = self
            .peers
            .values()
            .flat_map(|p| p.sync.reserved_hashes().copied())
            .collect();
        // Height-sorted fetch index — rebuilt once per header-set growth
        // (pages arrive in ~2000-header chunks), not once per peer per
        // tick: the previous per-peer `headers_by_height` collected and
        // sorted the entire index for every fill, which was the dominant
        // block-fetch cost once the header set grew large.
        let header_count = cs.tree().len();
        if header_count != self.fetch_index_headers {
            self.fetch_index = cs
                .tree()
                .headers_by_height()
                .iter()
                .map(|h| {
                    let hash = h.hash();
                    (
                        cs.tree().get(&hash).map(|n| n.height).unwrap_or(0),
                        hash,
                    )
                })
                .collect();
            self.fetch_index_headers = header_count;
        }
        // One shared scan: unfetched candidates above the connected
        // frontier (connected heights have bodies by definition), each
        // peer taking a slice until the aggregate budget binds.
        let frontier = cs.chain().len() as u32;
        let start = self
            .fetch_index
            .partition_point(|(h, _)| *h < frontier);
        let want_total = self.max_in_flight_total.saturating_sub(reserved.len());
        let candidates: Vec<BlockHash> = self.fetch_index[start..]
            .iter()
            .map(|(_, h)| *h)
            .filter(|h| !cs.have_body(h) && !reserved.contains(h))
            .take(want_total)
            .collect();
        let mut next = 0usize;
        for peer in self.peers.values_mut() {
            if next >= candidates.len() {
                break;
            }
            if !peer.session.established()
                || peer.sync.stalled()
                || peer.sync.in_flight() >= MAX_BLOCKS_IN_TRANSIT_PER_PEER
            {
                reserved.extend(peer.sync.reserved_hashes().copied());
                continue;
            }
            let take = crate::sync::MAX_BLOCKS_IN_TRANSIT_PER_PEER
                .saturating_sub(peer.sync.in_flight())
                .min(candidates.len() - next);
            let unfetched = &candidates[next..next + take];
            if let Some(req) = peer.sync.want_blocks_excluding(cs, unfetched, &reserved) {
                let _ = peer.session.send(&req);
            }
            next += take;
            reserved.extend(peer.sync.reserved_hashes().copied());
        }
        // Backlog: announced-but-unrequested blocks drain as slots free —
        // without this, inv bursts beyond the window are forgotten.
        let mut global_free = self.max_in_flight_total.saturating_sub(self.in_flight());
        for peer in self.peers.values_mut() {
            if !peer.session.established() {
                continue;
            }
            if let Some(req) = peer.sync.drain_pending(cs, global_free) {
                global_free = global_free.saturating_sub(peer.sync.in_flight());
                let _ = peer.session.send(&req);
            }
        }
    }

    /// One peer's event → replies and chainstate effects.
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        id: u64,
        peer: &mut PeerEntry<S>,
        event: SessionEvent,
        cs: &mut Chainstate,
        now: u32,
        addrbook: &mut AddrBook,
        headers_leader: &mut Option<u64>,
        announce_tip: &mut Option<u64>,
        announce_tx: &mut Option<(
            u64,
            avila_consensus::hash::Txid,
            avila_consensus::hash::Wtxid,
        )>,
        mempool: &mut avila_mempool::Mempool,
        global_free: &mut usize,
        events: &mut Vec<NetEvent>,
        dead: &mut Vec<(u64, DisconnectReason)>,
        serve_filters: bool,
    ) {
        match event {
            SessionEvent::Established => {
                if let Some(remote) = &peer.remote {
                    addrbook.mark_tried(remote);
                }
                let info = peer.session.peer().cloned().unwrap_or(PeerInfo {
                    version: 0,
                    services: 0,
                    start_height: 0,
                    user_agent: String::new(),
                    relay: false,
                    wtxid_relay: false,
                    addrv2: false,
                    recon: None,
                });
                if let Some(their) = info.recon.clone() {
                    peer.recon = Some(crate::recon::ReconPeer {
                        their_salt: their.salt,
                        our_salt: peer.session.recon_salt(),
                        they_send: their.is_sender,
                        they_respond: their.is_responder,
                    });
                    // First round a few seconds in — let early traffic
                    // (mempool asks, invs) settle first.
                    peer.next_recon = Instant::now() + RECON_FIRST_DELAY;
                }
                events.push(NetEvent::Connected {
                    peer: id,
                    info: Box::new(info),
                });
                let req = peer.sync.request_headers(cs);
                let _ = peer.session.send(&req);
            }
            SessionEvent::Message(Message::Headers(headers)) => {
                peer.last_announce = Some(i64::from(now));
                match peer.sync.on_headers(cs, &headers, now) {
                    Ok(outcome) => {
                        // Height of the last header this page indexed —
                        // Core's `synced_headers` (last common point this
                        // peer fed us).
                        if let Some(last) = headers.last()
                            && let Some(node) = cs.tree().get(&last.hash())
                        {
                            peer.synced_header_height = i64::from(node.height);
                        }
                        if let Some(next) = outcome.continuation {
                            // Only the headers leader keeps paging — Core
                            // pulls headers from one sync peer; other peers'
                            // first pages still validated above.
                            if headers_leader.is_none_or(|l| l == id) {
                                *headers_leader = Some(id);
                                let _ = peer.session.send(&next);
                            }
                        }
                        if !outcome.fetchable.is_empty() {
                            let offer =
                                &outcome.fetchable[..outcome.fetchable.len().min(*global_free)];
                            let before = peer.sync.in_flight();
                            if let Some(req) = peer.sync.want_blocks(cs, offer) {
                                *global_free =
                                    global_free.saturating_sub(peer.sync.in_flight() - before);
                                let _ = peer.session.send(&req);
                            }
                        }
                    }
                    Err(e) => dead.push((id, DisconnectReason::Misbehavior(e.to_string()))),
                }
            }
            SessionEvent::Message(Message::Inv(invs)) => {
                peer.last_announce = Some(i64::from(now));
                let missing: Vec<BlockHash> = invs
                    .iter()
                    .filter(|i| {
                        matches!(
                            i.inv_type,
                            crate::message::InvType::Block | crate::message::InvType::WitnessBlock
                        ) && !cs.have_body(&i.hash)
                    })
                    .map(|i| i.hash)
                    .collect();
                if !missing.is_empty() {
                    events.push(NetEvent::Announced {
                        peer: id,
                        missing: missing.clone(),
                    });
                }
                let before = peer.sync.in_flight();
                if let Some(req) = peer.sync.on_inv(cs, Some(mempool), &invs, *global_free) {
                    *global_free = global_free.saturating_sub(peer.sync.in_flight() - before);
                    let _ = peer.session.send(&req);
                }
            }
            SessionEvent::Message(Message::Block(block)) => {
                peer.last_block_time = Some(i64::from(now));
                match peer.sync.on_block(cs, &block, now) {
                    Ok(outcome) => {
                        peer.last_useful = Instant::now();
                        let connected_height =
                            if let avila_consensus::chainstate::Acceptance::Connected {
                                height,
                                ..
                            } = outcome.acceptance
                            {
                                peer.synced_block_height = i64::from(height);
                                Some(height)
                            } else {
                                None
                            };
                        if let Some(h) = connected_height {
                            mempool.on_block_connected(&block, h);
                        }
                        if let avila_consensus::chainstate::Acceptance::Connected {
                            reorged, ..
                        } = outcome.acceptance
                        {
                            if reorged {
                                // The disconnected branch's txs are
                                // unconfirmed again — re-admit them
                                // fork-adjacent block first (Core's
                                // DisconnectedBlockTransactions reverse
                                // drain, parent before child).
                                let gone = cs.take_disconnected();
                                mempool.refill_from_disconnected(&gone, cs, now, true, usize::MAX);
                            }
                            events.push(NetEvent::TipAdvanced(cs.chain().len() as u32 - 1));
                            // Relay the new tip to everyone except the peer
                            // that delivered it — they already know.
                            *announce_tip = Some(id);
                        }
                        // The tick fill pass re-feeds this peer's queue.
                    }
                    Err(e) => dead.push((id, DisconnectReason::Misbehavior(e.to_string()))),
                }
            }
            SessionEvent::Message(Message::SendHeaders) => {
                peer.wants_headers_announce = true;
            }
            SessionEvent::Message(Message::Tx(tx)) => {
                peer.last_tx_time = Some(i64::from(now));
                let wtxid = tx.wtxid();
                let txid_pre = tx.txid();
                peer.sync.on_tx(&txid_pre);
                if let Ok(txid) = mempool.accept_tx(tx, cs, now) {
                    *announce_tx = Some((id, txid, wtxid));
                }
                // Policy/consensus rejects are not misbehavior — the peer
                // stays (Core disconnects only for a score of them).
            }
            SessionEvent::Message(Message::GetHeaders(req)) => {
                let reply = PeerSync::serve_getheaders(cs, &req);
                let _ = peer.session.send(&reply);
            }
            SessionEvent::Message(Message::GetCFilters(req)) => {
                match PeerSync::serve_getcfilters(cs, serve_filters, &req) {
                    crate::sync::FilterReply::Serve(msgs) => {
                        for m in msgs {
                            if peer.session.send(&m).is_err() {
                                break;
                            }
                        }
                    }
                    crate::sync::FilterReply::Ignore => {}
                    crate::sync::FilterReply::Disconnect(reason) => {
                        dead.push((id, DisconnectReason::Misbehavior(reason.into())));
                    }
                }
            }
            SessionEvent::Message(Message::GetCFHeaders(req)) => {
                match PeerSync::serve_getcfheaders(cs, serve_filters, &req) {
                    crate::sync::FilterReply::Serve(msgs) => {
                        for m in msgs {
                            if peer.session.send(&m).is_err() {
                                break;
                            }
                        }
                    }
                    crate::sync::FilterReply::Ignore => {}
                    crate::sync::FilterReply::Disconnect(reason) => {
                        dead.push((id, DisconnectReason::Misbehavior(reason.into())));
                    }
                }
            }
            SessionEvent::Message(Message::GetCFCheckpt(req)) => {
                match PeerSync::serve_getcfcheckpt(cs, serve_filters, &req) {
                    crate::sync::FilterReply::Serve(msgs) => {
                        for m in msgs {
                            if peer.session.send(&m).is_err() {
                                break;
                            }
                        }
                    }
                    crate::sync::FilterReply::Ignore => {}
                    crate::sync::FilterReply::Disconnect(reason) => {
                        dead.push((id, DisconnectReason::Misbehavior(reason.into())));
                    }
                }
            }
            SessionEvent::Message(Message::GetData(reqs)) => {
                // A peer asking for a tx acknowledges its broadcast —
                // Core's RemoveUnbroadcastTx on getdata.
                for req in &reqs {
                    let txid = match req.inv_type {
                        crate::message::InvType::Tx | crate::message::InvType::WitnessTx => {
                            Some(avila_consensus::hash::Txid::from_bytes(req.hash.to_bytes()))
                        }
                        // MSG_WTX requests name the wtxid — resolve it.
                        crate::message::InvType::Wtx => mempool
                            .get_wtxid(&avila_consensus::hash::Wtxid::from_bytes(
                                req.hash.to_bytes(),
                            ))
                            .map(|tx| tx.txid()),
                        _ => None,
                    };
                    if let Some(txid) = txid {
                        mempool.clear_unbroadcast(&txid);
                    }
                }
                for reply in PeerSync::serve_getdata(cs, Some(mempool), &reqs) {
                    if peer.session.send(&reply).is_err() {
                        break; // send budget exhausted — drop the rest
                    }
                }
            }
            SessionEvent::Message(Message::NotFound(invs)) => {
                // The peer can't serve these — release the slots so the
                // fill pass reassigns them to another peer.
                peer.sync.on_notfound(&invs);
            }
            SessionEvent::Message(Message::ReqRecon(their_sketch)) => {
                // Responder side: attribute the decoded difference
                // against our own pool — ids we hold are their misses,
                // ids we don't are ours.
                let Some(link) = peer.recon else {
                    return;
                };
                let salt = link.our_salt ^ link.their_salt;
                let (our_ids, our_map) = recon_pool(mempool, salt);
                peer.recon_map = our_map;
                if let Some((reply, outcome)) =
                    crate::recon::ReconRound::respond(&their_sketch, &our_ids)
                {
                    let _ = peer.session.send(&reply);
                    if !outcome.responder_misses.is_empty() {
                        let _ = peer.session.send(&Message::ReconcilDiff {
                            ask_parents: 0,
                            short_ids: outcome.responder_misses,
                        });
                    }
                    // Txs they lack and we hold go out directly.
                    for id in outcome.initiator_misses {
                        if let Some(tx) = peer
                            .recon_map
                            .get(&id)
                            .and_then(|txid| mempool.get(txid))
                            .cloned()
                        {
                            let _ = peer.session.send(&Message::Tx(tx));
                        }
                    }
                }
            }
            SessionEvent::Message(Message::Sketch(reply_sk)) => {
                let Some(link) = peer.recon else {
                    return;
                };
                let salt = link.our_salt ^ link.their_salt;
                // Bisected close: each reply sketch decodes against our
                // matching half (lo first, fixed order).
                if let Some(mut bs) = peer.recon_bisect.take() {
                    let (half, is_lo) = if !bs.got_lo {
                        (&bs.lo, true)
                    } else {
                        (&bs.hi, false)
                    };
                    if let Some(round) = peer.recon_round.as_ref()
                        && let Some(misses) = round.close_bisected(&reply_sk, half)
                    {
                        bs.misses.extend(misses);
                    }
                    if is_lo {
                        bs.got_lo = true;
                        peer.recon_bisect = Some(bs);
                    } else {
                        // Both halves done — one diff ask for the lot.
                        peer.recon_round = None;
                        if !bs.misses.is_empty() {
                            let _ = peer.session.send(&Message::ReconcilDiff {
                                ask_parents: 0,
                                short_ids: bs.misses,
                            });
                        }
                    }
                    return;
                }
                let (our_ids, _) = recon_pool(mempool, salt);
                match peer.recon_round.take() {
                    Some(round) => match round.close(&reply_sk, &our_ids) {
                        Some(misses) if !misses.is_empty() => {
                            let _ = peer.session.send(&Message::ReconcilDiff {
                                ask_parents: 0,
                                short_ids: misses,
                            });
                        }
                        Some(_) => {}
                        // Over-capacity merge — ask the responder to
                        // bisect its pool; replies come back as two
                        // `sketch` messages.
                        None => {
                            let (lo, hi) = crate::recon::bisect(&our_ids, 31);
                            peer.recon_bisect = Some(ReconBisect {
                                lo,
                                hi,
                                got_lo: false,
                                misses: Vec::new(),
                            });
                            peer.recon_round = Some(round);
                            let _ = peer.session.send(&Message::ReqBisec);
                        }
                    },
                    None => {}
                }
            }
            SessionEvent::Message(Message::ReconcilDiff { short_ids, .. }) => {
                for id in short_ids {
                    if let Some(tx) = peer
                        .recon_map
                        .get(&id)
                        .and_then(|txid| mempool.get(txid))
                        .cloned()
                    {
                        let _ = peer.session.send(&Message::Tx(tx));
                    }
                }
            }
            SessionEvent::Message(Message::ReqBisec) => {
                // Split our pool at bit 31 and reply with two
                // half-capacity sketches — each half's difference is
                // half as wide, and failed halves bisect again on the
                // initiator's side.
                let Some(link) = peer.recon else {
                    return;
                };
                let salt = link.our_salt ^ link.their_salt;
                let (our_ids, _) = recon_pool(mempool, salt);
                let capacity = (our_ids.len() / 64).clamp(8, 512);
                let (lo, hi) = crate::recon::bisect_reply(&our_ids, 31, capacity);
                let _ = peer.session.send(&lo);
                let _ = peer.session.send(&hi);
            }
            SessionEvent::Message(Message::SendRecon(_)) => {
                // Late renegotiation is ignored — caps were fixed at
                // handshake.
            }
            SessionEvent::Message(Message::Mempool) => {
                // BIP35: advertise the whole pool. wtxid entries for
                // wtxidrelay peers, txid otherwise — one bounded inv.
                let by_wtxid = peer.session.peer().is_some_and(|i| i.wtxid_relay);
                let invs: Vec<crate::message::InvVector> = mempool
                    .txids()
                    .iter()
                    .filter_map(|txid| {
                        mempool.get(txid).map(|tx| crate::message::InvVector {
                            inv_type: if by_wtxid {
                                crate::message::InvType::Wtx
                            } else {
                                crate::message::InvType::Tx
                            },
                            hash: if by_wtxid {
                                BlockHash::from_bytes(*tx.wtxid().as_bytes())
                            } else {
                                BlockHash::from_bytes(*txid.as_bytes())
                            },
                        })
                    })
                    .collect();
                if !invs.is_empty() {
                    let _ = peer.session.send(&Message::Inv(invs));
                }
            }
            SessionEvent::Message(Message::GetAddr) => {
                let entries = addrbook
                    .sample()
                    .iter()
                    .map(|a| addr_v2_of(a, now))
                    .collect();
                let _ = peer.session.send(&Message::AddrV2(entries));
            }
            SessionEvent::Message(Message::Addr(entries)) => {
                peer.addr_processed += entries.len() as u64;
                addrbook.add_many(entries.iter().map(|e| (e.addr, e.time)), now);
            }
            SessionEvent::Message(Message::AddrV2(entries)) => {
                peer.addr_processed += entries.len() as u64;
                addrbook.add_many(
                    entries
                        .iter()
                        .filter_map(|e| net_addr_of_v2(e).map(|a| (a, e.time))),
                    now,
                );
            }
            SessionEvent::Message(Message::Pong(nonce)) => {
                if let Some((expected, sent_at)) = peer.ping_outstanding
                    && expected == nonce
                {
                    let rtt = sent_at.elapsed();
                    peer.ping_last = Some(rtt);
                    peer.ping_min = Some(peer.ping_min.map_or(rtt, |m| m.min(rtt)));
                    peer.ping_outstanding = None;
                }
            }
            SessionEvent::Message(_) => {}
        }
    }

    /// Total in-flight block requests across all peers.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.peers.values().map(|p| p.sync.in_flight()).sum()
    }

    /// The address book — peer discovery history (persist it alongside
    /// the chainstate so restarts keep their peer candidates).
    pub fn addrbook(&mut self) -> &mut AddrBook {
        &mut self.addrbook
    }

    /// The transaction pool.
    pub fn mempool(&mut self) -> &mut avila_mempool::Mempool {
        &mut self.mempool
    }

    /// Read-only view of the transaction pool (for query surfaces that
    /// only hold `&self`).
    #[must_use]
    pub fn mempool_ref(&self) -> &avila_mempool::Mempool {
        &self.mempool
    }

    /// The peers' ids (for scheduling decisions above this layer).
    #[must_use]
    pub fn peer_ids(&self) -> Vec<u64> {
        self.peers.keys().copied().collect()
    }

    /// Forcibly removes a peer (caller-initiated disconnect).
    pub fn disconnect(&mut self, id: u64) {
        self.drop_peer(id);
    }

    /// `ping` — queues a `ping` on every established session, measuring
    /// the send-queue backlog like Core's `Ping()` (each nonce is
    /// tracked in `ping_outstanding` so `getpeerinfo` reports RTTs).
    pub fn ping_all(&mut self) {
        for peer in self.peers.values_mut() {
            if !peer.session.established() {
                continue;
            }
            let nonce = peer.last_rx.elapsed().subsec_nanos().into();
            if peer.session.send(&Message::Ping(nonce)).is_ok() {
                peer.last_ping = Instant::now();
                peer.ping_outstanding = Some((nonce, Instant::now()));
            }
        }
    }

    /// `disconnectnode` by node id — `true` when a peer was dropped.
    pub fn disconnect_by_id(&mut self, id: u64) -> bool {
        if self.peers.contains_key(&id) {
            self.drop_peer(id);
            return true;
        }
        false
    }

    /// `getblockfrompeer` — asks `id` for `hash` via getdata, the way
    /// Core's `FetchBlock` requests `MSG_WITNESS_BLOCK`. `false` when
    /// no such peer exists or the send fails; arrival handling is the
    /// normal block path (the body parks or connects through
    /// `accept_block`).
    pub fn fetch_block(&mut self, id: u64, hash: BlockHash) -> bool {
        let Some(peer) = self.peers.get_mut(&id) else {
            return false;
        };
        peer.session
            .send(&Message::GetData(vec![crate::message::InvVector {
                inv_type: crate::message::InvType::WitnessBlock,
                hash,
            }]))
            .is_ok()
    }

    /// `disconnectnode` by `address` — Core matches the peer's
    /// `m_addr_name` string (`"ip:port"` for our dials; a bare host
    /// matches the address part). Returns whether anyone dropped.
    pub fn disconnect_by_addr(&mut self, addr: &str) -> bool {
        let hit: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                p.remote.as_ref().is_some_and(|r| {
                    let s = crate::addrman::addr_string(r);
                    s == addr || s.split(':').next() == Some(addr)
                })
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &hit {
            self.drop_peer(*id);
        }
        !hit.is_empty()
    }

    /// `getaddednodeinfo` — each `added_nodes` name plus its live
    /// connection list `(address, "inbound"|"outbound")`, the shape
    /// Core's `connected`/`addresses` fields render.
    pub fn added_node_info(&self) -> Vec<(String, Vec<(String, &'static str)>)> {
        self.added_nodes
            .iter()
            .map(|(name, _)| {
                let conns: Vec<(String, &'static str)> = self
                    .peers
                    .iter()
                    .filter(|(_, p)| {
                        p.remote.as_ref().is_some_and(|r| {
                            let s = crate::addrman::addr_string(r);
                            s == name.as_str() || s.split(':').next() == Some(name.as_str())
                        })
                    })
                    .map(|(_, p)| {
                        let addr = p
                            .remote
                            .as_ref()
                            .map(crate::addrman::addr_string)
                            .unwrap_or_default();
                        (addr, if p.inbound { "inbound" } else { "outbound" })
                    })
                    .collect();
                (name.clone(), conns)
            })
            .collect()
    }

    /// `disconnectnode` by subnet — drops every peer whose remote ip
    /// sits under `plen` bits of `net`.
    pub fn disconnect_by_subnet(&mut self, net: &[u8; 16], plen: u8) -> bool {
        let hit: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                p.remote
                    .as_ref()
                    .is_some_and(|r| crate::addrman::net_match(&r.ip, net, plen))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &hit {
            self.drop_peer(*id);
        }
        !hit.is_empty()
    }

    /// Is a live session already bound to `sock` — the addnode dial
    /// loop's "don't double-dial" check (Core's `FindNode` equivalent).
    fn connected_to(&self, sock: SocketAddr) -> bool {
        self.peers.values().any(|p| {
            p.remote
                .as_ref()
                .is_some_and(|r| crate::addrman::socket_addr(r) == sock)
        })
    }

    /// `addnode ... "add"` — Core's `connman.AddNode`: dedupe on the
    /// node string; `false` means it was already listed.
    pub fn add_node(&mut self, node: String, use_v2: bool) -> bool {
        if self.added_nodes.iter().any(|(n, _)| n == &node) {
            return false;
        }
        self.added_nodes.push((node, use_v2));
        true
    }

    /// `addnode ... "remove"` — `false` when the node wasn't listed.
    pub fn remove_node(&mut self, node: &str) -> bool {
        if let Some(i) = self.added_nodes.iter().position(|(n, _)| n == node) {
            self.added_nodes.remove(i);
            return true;
        }
        false
    }

    /// `setnetworkactive` — `false` drops every session (Core's
    /// `SetNetworkActive` disconnects all peers and stops dialing);
    /// `true` lets `tick_net` resume outbound maintenance.
    pub fn set_network_active(&mut self, on: bool) {
        self.network_active = on;
        if !on {
            let ids: Vec<u64> = self.peers.keys().copied().collect();
            for id in ids {
                self.drop_peer(id);
            }
            self.headers_leader = None;
        }
    }

    /// `getnetworkinfo`'s `networkactive`.
    #[must_use]
    pub fn network_active(&self) -> bool {
        self.network_active
    }

    /// The operator's `addnode` list (for `tick_net`'s dialing).
    #[must_use]
    pub fn added_nodes(&self) -> &[(String, bool)] {
        &self.added_nodes
    }

    /// Points ban persistence at `<net-datadir>/banlist.json` and
    /// loads any existing file — Core's `LoadBanlist` at startup.
    /// Expired entries are swept on load.
    pub fn set_banlist_path(&mut self, path: std::path::PathBuf, now: i64) {
        self.bans = crate::banman::BanList::load(&path).unwrap_or_default();
        self.bans.sweep(now);
        self.banlist_path = Some(path);
    }

    /// `BanMan::IsBanned` for a 16-byte address — the dial/accept gate.
    #[must_use]
    pub fn is_banned(&self, ip: &[u8; 16], now: i64) -> bool {
        self.bans.is_banned(ip, now)
    }

    /// `IsBanned(CSubNet)` — listed and active; setban's re-add check.
    #[must_use]
    pub fn is_subnet_banned(&self, net: &crate::banman::SubNet, now: i64) -> bool {
        self.bans.is_banned_subnet(net, now)
    }

    /// `listbanned`'s rows in Core's `CSubNet` sort order; expired
    /// entries are swept first (`GetBanned`'s view).
    pub fn banned_list(
        &mut self,
        now: i64,
    ) -> Vec<(crate::banman::SubNet, crate::banman::BanEntry)> {
        self.bans.sweep(now);
        self.bans.entries().map(|(n, e)| (*n, *e)).collect()
    }

    /// `setban add` — records the ban, drops every peer under it, and
    /// persists. `false` when the subnet is already listed (Core's
    /// `RPC_CLIENT_NODE_ALREADY_ADDED` path).
    pub fn ban(&mut self, net: crate::banman::SubNet, created: i64, until: i64) -> bool {
        if !self.bans.ban(net, created, until) {
            return false;
        }
        self.disconnect_by_subnet(&net.network, net.plen);
        self.save_bans();
        true
    }

    /// `setban remove` — `false` when the subnet wasn't listed
    /// (Core's "not previously manually banned" path).
    pub fn unban(&mut self, net: &crate::banman::SubNet) -> bool {
        if !self.bans.unban(net) {
            return false;
        }
        self.save_bans();
        true
    }

    /// `clearbanned` — drops the whole list and persists.
    pub fn clear_bans(&mut self) {
        self.bans.clear();
        self.save_bans();
    }

    /// `DumpBanlist` — best-effort like Core (a write failure loses
    /// the file, not the in-memory list).
    fn save_bans(&self) {
        if let Some(path) = &self.banlist_path {
            let _ = self.bans.save(path);
        }
    }
}

impl PeerManager<TcpStream> {
    /// Connects to `addr` over TCP and registers the outbound session.
    /// `use_v2` attempts BIP324 first and redials cleartext when the
    /// peer answers in v1 (Core's `ShouldReconnectV1`). Blocking until
    /// the transport handshake resolves — `tick` does the polling.
    pub fn connect(
        &mut self,
        addr: SocketAddr,
        magic: [u8; 4],
        our_version: u64, // nonce for build_version
        start_height: i32,
        use_v2: bool,
    ) -> Result<Option<u64>, SessionError> {
        let remote = crate::addrman::net_addr_of(addr, 0);
        // `BanMan::IsBanned` gates dialing — Core never opens a
        // connection to a banned address.
        if self.bans.is_banned(&remote.ip, (self.clock)()) {
            return Ok(None);
        }
        let mut version = build_version(our_version, start_height, remote, (self.clock)());
        if use_v2 {
            // GetLocalServices() — advertise NODE_P2P_V2 like Core's
            // `-v2transport`.
            version.services |= NODE_P2P_V2;
        }
        if self.serve_filters {
            version.services |= crate::message::NODE_COMPACT_FILTERS;
        }
        let session = dial(addr, magic, version, use_v2)?;
        Ok(self.add(session, Some(remote), false))
    }

    /// Connects to `target` through a SOCKS5 `proxy` and registers the
    /// outbound session — Core's `-proxy`/`onion` traffic path. The
    /// handshake itself runs over the proxied stream unchanged.
    pub fn connect_via(
        &mut self,
        proxy: &SocketAddr,
        target: &crate::proxy::SocksTarget,
        magic: [u8; 4],
        our_version: u64,
        start_height: i32,
    ) -> Result<Option<u64>, SessionError> {
        let remote = match target {
            crate::proxy::SocksTarget::Ip(addr) => crate::addrman::net_addr_of(*addr, 0),
            // A domain target has no numeric address to gossip.
            crate::proxy::SocksTarget::Domain(..) => NetAddr::unspecified(),
        };
        if self.bans.is_banned(&remote.ip, (self.clock)()) {
            return Ok(None);
        }
        let stream = crate::proxy::socks5_connect(proxy, target, Duration::from_secs(10))?;
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        let mut version = build_version(our_version, start_height, remote, (self.clock)());
        if self.serve_filters {
            version.services |= crate::message::NODE_COMPACT_FILTERS;
        }
        let session = PeerSession::initiate(stream, magic, version, SEND_BUDGET_PER_PEER)?;
        Ok(self.add(session, Some(remote), false))
    }

    /// Hand an accepted TCP socket to a handshake worker — the
    /// listener (sync loop) calls this per `accept()`; the worker
    /// detects the peer's transport and runs the responder-side
    /// handshake off the tick, reporting through the inbound channel.
    /// `MAX_PENDING_ACCEPTS` bounds the pool a connect-flood could
    /// grow; a full queue just drops the socket.
    pub fn accept_peer(
        &mut self,
        stream: TcpStream,
        remote: SocketAddr,
        magic: [u8; 4],
        our_version: u64,
        start_height: i32,
    ) {
        let pending = self.pending_accepts.clone();
        if pending.load(std::sync::atomic::Ordering::Relaxed) >= MAX_PENDING_ACCEPTS {
            return; // drop the socket — the caller closes it
        }
        let tx = self.inbound_tx.clone();
        let remote_addr = crate::addrman::net_addr_of(remote, 0);
        let mut version = build_version(our_version, start_height, remote_addr, (self.clock)());
        if self.serve_filters {
            version.services |= crate::message::NODE_COMPACT_FILTERS;
        }
        if self.v2transport {
            version.services |= NODE_P2P_V2;
        }
        let v2 = self.v2transport;
        pending.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::thread::spawn(move || {
            let outcome = accept_one(stream, magic, version, v2);
            pending.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            let _ = tx.send((remote, outcome));
        });
    }

    /// Admits every completed inbound handshake — ban check, then
    /// `add_inbound`'s slot/eviction rules. Returns the admitted ids.
    pub fn drain_inbounds(&mut self) -> Vec<u64> {
        let mut admitted = Vec::new();
        while let Ok((addr, result)) = self.inbound_rx.try_recv() {
            let Ok(session) = result else { continue };
            let remote = crate::addrman::net_addr_of(addr, 0);
            if !self.network_active || self.bans.is_banned(&remote.ip, (self.clock)()) {
                continue;
            }
            if let Some(id) = self.add_inbound_from(session, Some(remote)) {
                admitted.push(id);
            }
        }
        admitted
    }

    /// Resolves `params.dns_seeds` into the address book — the bootstrap
    /// path for real networks (regtest ships no seeds). Returns how many
    /// addresses were learned. Blocking DNS; run before the tick loop.
    pub fn seed_from_dns(&mut self, params: &avila_consensus::params::Params, now: u32) -> usize {
        let addrs = addrman::resolve_seeds(params.dns_seeds, params.default_port);
        let n = addrs.len();
        self.addrbook
            .add_many(addrs.into_iter().map(|a| (a, now)), now);
        n
    }

    /// `tick` plus connectivity maintenance: any disconnect this round
    /// immediately triggers `maintain_outbounds`, so the peer set
    /// self-heals from the address book.
    pub fn tick_net(
        &mut self,
        cs: &mut Chainstate,
        now: u32,
        magic: [u8; 4],
        start_height: i32,
    ) -> Vec<NetEvent> {
        let events = self.tick(cs, now);
        // Maintain on any disconnect, plus periodically while the peer
        // set isn't full — an empty set emits no events, so without the
        // cadence a starved node (fresh start, or `setnetworkactive`
        // re-enable) would never redial.
        let due = self
            .last_maintained
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(2));
        if events
            .iter()
            .any(|e| matches!(e, NetEvent::Disconnected { .. }))
            || (due && self.has_slot())
        {
            self.last_maintained = Some(Instant::now());
            self.maintain_outbounds(magic, start_height);
        }
        events
    }

    /// Drains completed dial workers into sessions, then queues new
    /// dials for the operator's `addnode` entries plus address-book
    /// candidates until the peer set is full — the caller runs this
    /// between `tick`s to keep outbound connectivity up. Dials run on
    /// worker threads (`TcpStream::connect_timeout`), so unreachable
    /// candidates never block the sync loop; sessions register here on
    /// completion. No-op while `setnetworkactive false` is in effect.
    /// Returns the endpoints attempted this round.
    pub fn maintain_outbounds(&mut self, magic: [u8; 4], start_height: i32) -> Vec<SocketAddr> {
        let mut dialed = Vec::new();
        // Completed workers first: a ban or a full peer set that
        // landed mid-dial still applies — Core rechecks IsBanned after
        // connect for the same reason.
        while let Ok((addr, result)) = self.dial_rx.try_recv() {
            self.pending_dials.remove(&addr);
            let Ok(session) = result else { continue };
            let remote = addrman::net_addr_of(addr, 0);
            // A ban or a full peer set that landed mid-dial still
            // applies — Core rechecks IsBanned after connect.
            let admissible = self.network_active
                && self.has_slot()
                && !self.bans.is_banned(&remote.ip, (self.clock)());
            if admissible {
                self.add(session, Some(remote), false);
            }
        }
        if !self.network_active {
            return dialed;
        }
        // addnode entries are operator intent — try them ahead of the
        // book. A 30s retry backoff keeps a dead entry from
        // re-queueing every round.
        for (node, use_v2) in self.added_nodes.clone() {
            if !self.outbound_open() {
                break;
            }
            if self
                .addnode_dial
                .get(&node)
                .is_some_and(|t| t.elapsed() < Duration::from_secs(30))
            {
                continue;
            }
            if let Ok(addrs) = node.as_str().to_socket_addrs() {
                let socks: Vec<SocketAddr> = addrs.collect();
                // Already talking to this node — Core's AddNode thread
                // skips connected entries rather than double-dialing.
                // Don't stamp the backoff either, so a drop redials fast.
                if socks
                    .iter()
                    .any(|s| self.connected_to(*s) || self.pending_dials.contains(s))
                {
                    continue;
                }
                self.addnode_dial.insert(node.clone(), Instant::now());
                let now = (self.clock)();
                for sock in socks {
                    if !self.outbound_open() {
                        break;
                    }
                    // Banned addresses are never dialed (Core's
                    // `IsBanned` gate in the addnode/open threads).
                    if self.is_banned(&addrman::net_addr_of(sock, 0).ip, now) {
                        continue;
                    }
                    // addnode's `v2transport` flag overrides the
                    // `-v2transport` default for this peer.
                    self.queue_dial(sock, use_v2, magic, start_height, &mut dialed);
                }
            }
        }
        let now = (self.clock)();
        // `select` is deterministic, so each probe marks its candidate —
        // the round is bounded by the book size and a banned candidate
        // can't starve or spin the loop.
        let probes_left = self.addrbook.len();
        let mut tried = 0usize;
        while self.outbound_open()
            && tried < probes_left
            && let Some(candidate) = self.addrbook.select()
        {
            tried += 1;
            self.addrbook.mark_attempt(&candidate);
            if self.is_banned(&candidate.ip, now) {
                continue; // banned candidates aren't dialed
            }
            // Already connected or dialing — Core's
            // `AlreadyConnectedTo`/`FindNode` check; the book may
            // still carry peers we established sessions with.
            let sock = addrman::socket_addr(&candidate);
            if self.connected_to(sock) || self.pending_dials.contains(&sock) {
                continue;
            }
            // Automatic outbounds use the `-v2transport` setting —
            // Core's `use_v2transport` on OpenNetworkConnection.
            self.queue_dial(sock, self.v2transport, magic, start_height, &mut dialed);
        }
        dialed
    }

    /// Whether another outbound peer may be *dialed* — open slots minus
    /// the dials already in flight, so the worker count is bounded by
    /// `max_peers` even when every candidate is unreachable.
    fn outbound_open(&self) -> bool {
        self.peers.len() + self.pending_dials.len() < self.max_peers
    }

    /// Spawns a dial worker for `addr` — the worker's only job is the
    /// blocking `connect_timeout`; everything else (session init,
    /// ban recheck, slot check) happens on the tick that drains it.
    fn queue_dial(
        &mut self,
        addr: SocketAddr,
        use_v2: bool,
        magic: [u8; 4],
        start_height: i32,
        dialed: &mut Vec<SocketAddr>,
    ) {
        if !self.pending_dials.insert(addr) {
            return; // already in flight
        }
        dialed.push(addr);
        let tx = self.dial_tx.clone();
        let mut version = build_version(
            addr.port() as u64,
            start_height,
            addrman::net_addr_of(addr, 0),
            (self.clock)(),
        );
        if use_v2 {
            version.services |= NODE_P2P_V2;
        }
        if self.serve_filters {
            version.services |= crate::message::NODE_COMPACT_FILTERS;
        }
        std::thread::spawn(move || {
            let _ = tx.send((addr, dial(addr, magic, version, use_v2)));
        });
    }
}

/// The per-dial worker timeout — Core's `connect()` default is 5s
/// (`nConnectTimeout` is only honored by proxies; direct dials use
/// the same bound here).
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// One dial worker's product — a live `PeerSession` (v1, or v2 with
/// the BIP324 handshake already done) or the failure.
type DialOutcome = Result<PeerSession<TcpStream>, SessionError>;

/// `connect` + optional BIP324 handshake + nonblocking flip — shared
/// by [`PeerManager::connect`] and the `queue_dial` workers. On
/// `V1Fallback` the socket is dropped and the peer redialed in v1 —
/// Core's `ShouldReconnectV1` (a v1-only peer can't parse the
/// ellswift bytes we already sent).
/// Inbound handshakes in flight at once — past this cap the listener
/// drops accepted sockets rather than queue unbounded workers.
const MAX_PENDING_ACCEPTS: usize = 32;

/// The v1 transport's fixed 16-byte prefix on the wire: network magic
/// followed by the padded `version` command. An inbound peer sending
/// anything else is attempting BIP324 — exactly Core's
/// `Transport::ReceivedMessage` discriminator.
fn v1_version_prefix(magic: [u8; 4]) -> [u8; 16] {
    let mut p = [0u8; 16];
    p[..4].copy_from_slice(&magic);
    // The 12-byte command field: "version" + five NULs.
    p[4..11].copy_from_slice(b"version");
    p
}

/// Responder side of a fresh inbound connection: peek at the first
/// bytes to pick the transport, run the matching handshake (blocking,
/// bounded by `HANDSHAKE_TIMEOUT` on the socket), then return a
/// nonblocking session for `add_inbound`. v1 peers fall through to
/// `PeerSession::accept` — their bytes stay in the socket for the
/// session's own decoder.
fn accept_one(
    mut stream: TcpStream,
    magic: [u8; 4],
    version: Version,
    want_v2: bool,
) -> DialOutcome {
    stream.set_nodelay(true)?;
    if !want_v2 {
        stream.set_nonblocking(true)?;
        return Ok(PeerSession::accept(
            stream,
            magic,
            version,
            SEND_BUDGET_PER_PEER,
        ));
    }
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    // Peek until the full discriminator arrives — TCP may fragment the
    // peer's first write.
    let mut probe = [0u8; 16];
    let want = v1_version_prefix(magic);
    loop {
        let n = stream.peek(&mut probe)?;
        if n >= 16 || probe[..n] != want[..n] {
            break;
        }
    }
    if probe == want {
        stream.set_read_timeout(None)?;
        stream.set_nonblocking(true)?;
        return Ok(PeerSession::accept(
            stream,
            magic,
            version,
            SEND_BUDGET_PER_PEER,
        ));
    }
    match crate::bip324::respond_handshake(&mut stream, magic) {
        Ok(channel) => {
            stream.set_read_timeout(None)?;
            stream.set_nonblocking(true)?;
            Ok(PeerSession::accept_v2_channel(
                stream,
                magic,
                version,
                SEND_BUDGET_PER_PEER,
                channel,
            ))
        }
        Err(e) => Err(SessionError::Io(e)),
    }
}

fn dial(addr: SocketAddr, magic: [u8; 4], version: Version, want_v2: bool) -> DialOutcome {
    let stream = TcpStream::connect_timeout(&addr, DIAL_TIMEOUT)?;
    stream.set_nodelay(true)?;
    if want_v2 {
        // The handshake blocks for at most the handshake timeout —
        // the caller thread (dial worker or RPC) bounds it.
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        match PeerSession::initiate_v2(stream, magic, version.clone(), SEND_BUDGET_PER_PEER) {
            Err(SessionError::V1Fallback) => {
                let stream = TcpStream::connect_timeout(&addr, DIAL_TIMEOUT)?;
                stream.set_nodelay(true)?;
                stream.set_nonblocking(true)?;
                return PeerSession::initiate(stream, magic, version, SEND_BUDGET_PER_PEER);
            }
            Ok(mut session) => {
                let s = session.stream_mut();
                s.set_read_timeout(None)?;
                s.set_nonblocking(true)?;
                return Ok(session);
            }
            Err(e) => return Err(e),
        }
    }
    stream.set_nonblocking(true)?;
    PeerSession::initiate(stream, magic, version, SEND_BUDGET_PER_PEER)
}

/// `AddrV2Entry` → `NetAddr` for the networks we understand (IPv4 = 1,
/// IPv6 = 2); other BIP155 networks are opaque and skipped.
fn net_addr_of_v2(e: &AddrV2Entry) -> Option<NetAddr> {
    let ip = match (e.network, e.addr.len()) {
        (1, 4) => std::net::Ipv4Addr::new(e.addr[0], e.addr[1], e.addr[2], e.addr[3])
            .to_ipv6_mapped()
            .octets(),
        (2, 16) => <[u8; 16]>::try_from(e.addr.as_slice()).ok()?,
        _ => return None,
    };
    Some(NetAddr {
        services: e.services,
        ip,
        port: e.port,
    })
}

/// `NetAddr` → `AddrV2Entry` for `getaddr` replies.
fn addr_v2_of(addr: &NetAddr, now: u32) -> AddrV2Entry {
    let v6 = std::net::Ipv6Addr::from(addr.ip);
    let (network, bytes) = match v6.to_ipv4_mapped() {
        Some(v4) => (1, v4.octets().to_vec()),
        None => (2, addr.ip.to_vec()),
    };
    AddrV2Entry {
        time: now,
        services: addr.services,
        network,
        addr: bytes,
        port: addr.port,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::message::{
        AddrEntry, GetHeaders, InvType, InvVector, NODE_NETWORK, PROTOCOL_VERSION, Version,
    };
    use crate::testchain::{chain_blocks, regtest};
    use crate::testpipe::{self, End};
    use avila_consensus::hash::BlockHash;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda]; // regtest
    const NOW: u32 = 1_800_000_000;
    const BUDGET: usize = 1 << 20;

    fn peer_version(start_height: i32) -> Version {
        Version {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK,
            timestamp: i64::from(NOW),
            addr_recv: NetAddr::unspecified(),
            addr_from: NetAddr::unspecified(),
            nonce: 7,
            user_agent: "/peer:0.0/".to_string(),
            start_height,
            relay: true,
        }
    }

    /// A manager whose one outbound session rides `peer`'s other end.
    fn managed_peer() -> (PeerManager<End>, End, u64) {
        let (us_end, peer_end) = testpipe::pair();
        let session = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(1, 0, NetAddr::unspecified(), i64::from(NOW)),
            BUDGET,
        )
        .expect("session");
        let mut mgr = PeerManager::new(8);
        let id = mgr.add_outbound(session).expect("slot");
        (mgr, peer_end, id)
    }

    /// Drives the scripted peer through the Core handshake: our version →
    /// their version → our wtxidrelay/sendaddrv2/verack → their verack.
    fn handshake(mgr: &mut PeerManager<End>, peer: &mut End, cs: &mut Chainstate) -> Vec<NetEvent> {
        let mut events = mgr.tick(cs, NOW);
        let sent = testpipe::drain(peer, MAGIC);
        assert!(
            matches!(sent.first(), Some(Message::Version(_))),
            "{sent:?}"
        );

        testpipe::inject(peer, MAGIC, &Message::Version(peer_version(600)));
        events.extend(mgr.tick(cs, NOW));
        let sent = testpipe::drain(peer, MAGIC);
        assert!(
            sent.iter().any(|m| matches!(m, Message::Verack)),
            "{sent:?}"
        );

        testpipe::inject(peer, MAGIC, &Message::Verack);
        events.extend(mgr.tick(cs, NOW));
        events
    }

    #[test]
    fn peer_cap_enforced() {
        let mut mgr = PeerManager::<End>::new(1);
        let (us1, _p1) = testpipe::pair();
        mgr.add_outbound(
            PeerSession::initiate(
                us1,
                MAGIC,
                build_version(1, 0, NetAddr::unspecified(), i64::from(NOW)),
                BUDGET,
            )
            .unwrap(),
        );
        let (us2, _p2) = testpipe::pair();
        assert!(
            mgr.add_outbound(
                PeerSession::initiate(
                    us2,
                    MAGIC,
                    build_version(2, 0, NetAddr::unspecified(), i64::from(NOW)),
                    BUDGET
                )
                .unwrap()
            )
            .is_none()
        );
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn established_peer_is_asked_for_headers() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        let events = handshake(&mut mgr, &mut peer, &mut cs);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, NetEvent::Connected { .. }))
        );
        // The post-handshake getheaders is queued during Established's
        // dispatch and flushes on the next tick.
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        assert!(
            sent.iter().any(|m| matches!(m, Message::GetHeaders(_))),
            "{sent:?}"
        );
    }

    #[test]
    fn reqrecon_is_answered_with_sketch_and_reconcildiff() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        // Handshake with the peer negotiating recon caps.
        let mut events = mgr.tick(&mut cs, NOW);
        let _ = testpipe::drain(&mut peer, MAGIC);
        testpipe::inject(&mut peer, MAGIC, &Message::Version(peer_version(600)));
        testpipe::inject(
            &mut peer,
            MAGIC,
            &Message::SendRecon(crate::message::SendRecon {
                is_sender: true,
                is_responder: true,
                version: crate::recon::RECON_VERSION,
                salt: 0xABCD,
            }),
        );
        events.extend(mgr.tick(&mut cs, NOW));
        testpipe::inject(&mut peer, MAGIC, &Message::Verack);
        events.extend(mgr.tick(&mut cs, NOW));
        assert!(events.iter().any(|e| matches!(e, NetEvent::Connected { .. })));

        // Peer opens a round over its own 3-id pool; ours is empty.
        let mut sk = crate::sketch::Sketch::new(8);
        for id in [7u32, 8, 9] {
            sk.add(id);
        }
        testpipe::inject(
            &mut peer,
            MAGIC,
            &Message::ReqRecon(sk.serialize()),
        );
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        assert!(sent.iter().any(|m| matches!(m, Message::Sketch(_))), "{sent:?}");
        let rd = sent.iter().find_map(|m| match m {
            Message::ReconcilDiff { short_ids, .. } => Some(short_ids.clone()),
            _ => None,
        });
        assert_eq!(
            rd.map(|mut v| { v.sort(); v }),
            Some(vec![7, 8, 9]),
            "{sent:?}"
        );
    }

    #[test]
    fn recon_peer_opens_round_when_due() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        mgr.tick(&mut cs, NOW);
        let _ = testpipe::drain(&mut peer, MAGIC);
        testpipe::inject(&mut peer, MAGIC, &Message::Version(peer_version(600)));
        testpipe::inject(
            &mut peer,
            MAGIC,
            &Message::SendRecon(crate::message::SendRecon {
                is_sender: true,
                is_responder: true,
                version: crate::recon::RECON_VERSION,
                salt: 0x55,
            }),
        );
        mgr.tick(&mut cs, NOW);
        testpipe::inject(&mut peer, MAGIC, &Message::Verack);
        mgr.tick(&mut cs, NOW);
        // Back-date the due time so recon_pass opens immediately.
        if let Some((_, p)) = mgr.peers.iter_mut().next() {
            p.next_recon = std::time::Instant::now() - Duration::from_secs(1);
        }
        // recon_pass queues the ReqRecon; it flushes on the next tick.
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        assert!(sent.iter().any(|m| matches!(m, Message::ReqRecon(_))), "{sent:?}");
    }

    #[test]
    fn peer_eof_disconnects() {
        let (mut mgr, mut peer, id) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer, &mut cs);
        drop(peer);
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, NetEvent::Disconnected { peer: p, .. } if *p == id)),
            "{events:?}"
        );
        assert!(mgr.is_empty());
    }

    #[test]
    fn headers_then_blocks_connect_chain() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 3);
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC); // drop our getheaders

        // Peer announces 3 headers.
        let headers: Vec<_> = blocks.iter().map(|b| b.header).collect();
        testpipe::inject(&mut peer, MAGIC, &Message::Headers(headers));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        // We asked for the block bodies.
        let sent = testpipe::drain(&mut peer, MAGIC);
        let wanted: Vec<BlockHash> = sent
            .iter()
            .filter_map(|m| match m {
                Message::GetData(vs) => Some(vs.iter().map(|v| v.hash).collect::<Vec<_>>()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(wanted.len(), 3, "{sent:?}");

        // Peer delivers all three bodies — each connects.
        for b in &blocks {
            testpipe::inject(&mut peer, MAGIC, &Message::Block(b.clone()));
        }
        let events = mgr.tick(&mut cs, NOW);
        assert_eq!(cs.chain().len(), 4); // genesis + 3
        assert!(
            events.iter().any(|e| matches!(e, NetEvent::TipAdvanced(3))),
            "{events:?}"
        );
    }

    #[test]
    fn garbage_headers_evict_peer() {
        let (mut mgr, mut peer, id) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);

        // A header whose prev is nowhere in our tree.
        let params = *cs.tree().params();
        let junk = avila_consensus::header::BlockHeader {
            prev_block_hash: BlockHash::from_bytes([0xaa; 32]),
            ..params.genesis_header
        };
        testpipe::inject(&mut peer, MAGIC, &Message::Headers(vec![junk]));
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            events.iter().any(|e| matches!(
                e,
                NetEvent::Disconnected {
                    peer: p,
                    reason: DisconnectReason::Misbehavior(_)
                } if *p == id
            )),
            "{events:?}"
        );
    }

    #[test]
    fn peer_is_served_headers() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 3);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);

        // Peer asks from genesis — we serve all 3 headers.
        let req = GetHeaders {
            locator: vec![cs.tree().headers_by_height()[0].hash()],
            stop: BlockHash::ZERO,
        };
        testpipe::inject(&mut peer, MAGIC, &Message::GetHeaders(req));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        match sent.iter().find(|m| matches!(m, Message::Headers(_))) {
            Some(Message::Headers(hs)) => {
                assert_eq!(hs.len(), 3);
                assert_eq!(hs[0].hash(), blocks[0].block_hash());
            }
            _ => panic!("no headers reply in {sent:?}"),
        }
    }

    #[test]
    fn inv_announcement_triggers_fetch() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 2);
        // Index the headers first so inv bodies are fetchable.
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);

        let invs = vec![InvVector {
            inv_type: InvType::WitnessBlock,
            hash: blocks[0].block_hash(),
        }];
        testpipe::inject(&mut peer, MAGIC, &Message::Inv(invs));
        let events = mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, NetEvent::Announced { missing, .. } if missing.len() == 1)),
            "{events:?}"
        );
        let sent = testpipe::drain(&mut peer, MAGIC);
        assert!(
            sent.iter().any(|m| matches!(m, Message::GetData(_))),
            "{sent:?}"
        );
    }

    /// A second managed peer; returns (its scripted end, its id).
    fn add_peer(mgr: &mut PeerManager<End>) -> (End, u64) {
        let (us_end, peer_end) = testpipe::pair();
        let session = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(9, 0, NetAddr::unspecified(), i64::from(NOW)),
            BUDGET,
        )
        .expect("session");
        let id = mgr.add_outbound(session).expect("slot");
        (peer_end, id)
    }

    /// Same handshake as `handshake` but for an arbitrary peer end.
    fn handshake_peer(
        mgr: &mut PeerManager<End>,
        peer: &mut End,
        cs: &mut Chainstate,
    ) -> Vec<NetEvent> {
        handshake(mgr, peer, cs)
    }

    #[test]
    fn second_peer_takes_over_interrupted_download() {
        let (mut mgr, mut peer_a, id_a) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 4);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        handshake(&mut mgr, &mut peer_a, &mut cs);
        testpipe::drain(&mut peer_a, MAGIC);
        // A ends its headers phase (empty page = "we're at your tip").
        testpipe::inject(&mut peer_a, MAGIC, &Message::Headers(vec![]));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer_a, MAGIC);
        let a_wants = sent
            .iter()
            .filter(|m| matches!(m, Message::GetData(_)))
            .count();
        assert_eq!(a_wants, 1, "{sent:?}");

        // A delivers only the first block, then dies mid-download.
        testpipe::inject(&mut peer_a, MAGIC, &Message::Block(blocks[0].clone()));
        mgr.tick(&mut cs, NOW);
        assert_eq!(cs.chain().len(), 2);
        drop(peer_a);
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, NetEvent::Disconnected { peer: p, .. } if *p == id_a))
        );

        // B connects, handshakes; the fill pass hands B the 3 stragglers.
        let (mut peer_b, _id_b) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        testpipe::drain(&mut peer_b, MAGIC);
        testpipe::inject(&mut peer_b, MAGIC, &Message::Headers(vec![]));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer_b, MAGIC);
        let wanted: Vec<BlockHash> = sent
            .iter()
            .filter_map(|m| match m {
                Message::GetData(vs) => Some(vs.iter().map(|v| v.hash).collect::<Vec<_>>()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(
            wanted.len(),
            3,
            "B should fetch only the undelivered blocks: {sent:?}"
        );
        for b in &blocks[1..] {
            testpipe::inject(&mut peer_b, MAGIC, &Message::Block(b.clone()));
        }
        mgr.tick(&mut cs, NOW);
        assert_eq!(cs.chain().len(), 5);
    }

    #[test]
    fn two_peers_do_not_duplicate_requests() {
        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 4);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        let (mut peer_b, _id_b) = add_peer(&mut mgr);
        handshake(&mut mgr, &mut peer_a, &mut cs);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        // Both peers conclude their headers phase.
        testpipe::inject(&mut peer_a, MAGIC, &Message::Headers(vec![]));
        testpipe::inject(&mut peer_b, MAGIC, &Message::Headers(vec![]));

        // Collect every getdata both pipes receive over a few ticks —
        // the fill pass may have queued A's request while B was still
        // handshaking, so tally across all drains, not one.
        let count_getdata = |msgs: &[Message]| -> usize {
            msgs.iter()
                .filter_map(|m| match m {
                    Message::GetData(vs) => Some(vs.len()),
                    _ => None,
                })
                .sum()
        };
        let mut requested = 0usize;
        for _ in 0..4 {
            mgr.tick(&mut cs, NOW);
            requested += count_getdata(&testpipe::drain(&mut peer_a, MAGIC));
            requested += count_getdata(&testpipe::drain(&mut peer_b, MAGIC));
        }
        // All 4 blocks requested exactly once across the pair.
        assert_eq!(requested, 4);
    }

    #[test]
    fn connected_tip_is_announced_to_other_peers() {
        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 2);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        let (mut peer_b, _id_b) = add_peer(&mut mgr);
        let (mut peer_c, _id_c) = add_peer(&mut mgr);
        handshake(&mut mgr, &mut peer_a, &mut cs);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        handshake_peer(&mut mgr, &mut peer_c, &mut cs);
        testpipe::drain(&mut peer_a, MAGIC);
        testpipe::drain(&mut peer_b, MAGIC);
        testpipe::drain(&mut peer_c, MAGIC);
        // B opted into headers announcements; C did not.
        testpipe::inject(&mut peer_b, MAGIC, &Message::SendHeaders);
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_b, MAGIC);

        // A delivers the block — the tip advances and B is told via
        // headers; A (the source) hears nothing back.
        testpipe::inject(&mut peer_a, MAGIC, &Message::Block(blocks[0].clone()));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent_a = testpipe::drain(&mut peer_a, MAGIC);
        let sent_b = testpipe::drain(&mut peer_b, MAGIC);
        let sent_c = testpipe::drain(&mut peer_c, MAGIC);
        assert!(
            !sent_a
                .iter()
                .any(|m| matches!(m, Message::Headers(_) | Message::Inv(_))),
            "source peer must not be re-announced: {sent_a:?}"
        );
        assert!(
            sent_b.iter().any(|m| matches!(
                m,
                Message::Headers(hs) if hs.len() == 1 && hs[0].hash() == blocks[0].block_hash()
            )),
            "B should get a headers announcement: {sent_b:?}"
        );
        assert!(
            sent_c.iter().any(|m| matches!(
                m,
                Message::Inv(vs) if vs.iter().any(|v| v.inv_type == crate::message::InvType::Block
                    && v.hash == blocks[0].block_hash())
            )),
            "C should get an inv announcement: {sent_c:?}"
        );
    }

    fn add_inbound_peer(mgr: &mut PeerManager<End>) -> Option<(End, u64)> {
        let (us_end, peer_end) = testpipe::pair();
        let session = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(9, 0, NetAddr::unspecified(), i64::from(NOW)),
            BUDGET,
        )
        .expect("session");
        mgr.add_inbound(session).map(|id| (peer_end, id))
    }

    #[test]
    fn full_set_evicts_least_useful_inbound() {
        let mut mgr = PeerManager::new(2);
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 1);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        let (mut p1, id1) = add_inbound_peer(&mut mgr).expect("slot");
        let (_p2, id2) = add_inbound_peer(&mut mgr).expect("slot");
        handshake(&mut mgr, &mut p1, &mut cs);
        testpipe::drain(&mut p1, MAGIC);
        // p1 delivers a block → becomes the more recently useful peer.
        testpipe::inject(&mut p1, MAGIC, &Message::Block(blocks[0].clone()));
        mgr.tick(&mut cs, NOW);
        // The set is full: a third inbound evicts the least recently
        // useful one — p2, not p1.
        let (_p3, id3) = add_inbound_peer(&mut mgr).expect("eviction admits");
        assert!(mgr.peers.contains_key(&id1), "useful peer survives");
        assert!(!mgr.peers.contains_key(&id2), "stale peer evicted");
        assert!(mgr.peers.contains_key(&id3));
    }

    #[test]
    fn outbound_peers_are_never_evicted_for_inbound() {
        let mut mgr = PeerManager::new(1);
        let (_us_end, _peer_end) = testpipe::pair();
        let session = PeerSession::initiate(
            _us_end,
            MAGIC,
            build_version(9, 0, NetAddr::unspecified(), i64::from(NOW)),
            BUDGET,
        )
        .expect("session");
        let id = mgr.add_outbound(session).expect("slot");
        // Full of outbound peers only — inbound admission cannot evict.
        assert!(add_inbound_peer(&mut mgr).is_none());
        assert!(mgr.peers.contains_key(&id));
    }

    #[test]
    fn global_in_flight_budget_bounds_reservations() {
        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        mgr.set_max_in_flight_total(3);
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 8);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        let (mut peer_b, _id_b) = add_peer(&mut mgr);
        handshake(&mut mgr, &mut peer_a, &mut cs);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        testpipe::drain(&mut peer_a, MAGIC);
        testpipe::drain(&mut peer_b, MAGIC);
        // End both headers phases so the fill pass feeds block queues.
        for p in [&mut peer_a, &mut peer_b] {
            testpipe::inject(p, MAGIC, &Message::Headers(vec![]));
        }
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        assert_eq!(mgr.in_flight(), 3);
    }

    #[test]
    fn competing_branch_reorgs_the_connected_chain() {
        use crate::testchain::fork_blocks;
        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        let mut cs = regtest();
        // Active chain: genesis + a1..a3, all connected.
        let a_blocks = chain_blocks(&cs, 3);
        for b in &a_blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        assert_eq!(cs.chain().last().copied(), Some(a_blocks[2].block_hash()));
        handshake(&mut mgr, &mut peer_a, &mut cs);
        testpipe::drain(&mut peer_a, MAGIC);

        // The peer announces a fork off a1 with more work: f2,f3,f4.
        let fork = fork_blocks(&cs, &a_blocks[0].header, 2, 3);
        let headers: Vec<_> = fork.iter().map(|b| b.header).collect();
        testpipe::inject(&mut peer_a, MAGIC, &Message::Headers(headers));
        let mut events = mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        // The fork headers indexed → we asked for the fork bodies.
        let sent = testpipe::drain(&mut peer_a, MAGIC);
        assert!(
            sent.iter()
                .any(|m| matches!(m, Message::GetData(vs) if !vs.is_empty())),
            "fork bodies should be requested: {sent:?}"
        );
        // Deliver the fork bodies — the branch outworks us at f4.
        for b in &fork {
            testpipe::inject(&mut peer_a, MAGIC, &Message::Block(b.clone()));
            events.extend(mgr.tick(&mut cs, NOW));
        }
        assert_eq!(
            cs.chain().last().copied(),
            Some(fork[2].block_hash()),
            "chain should reorg onto the stronger fork"
        );
        assert!(
            events.iter().any(|e| matches!(e, NetEvent::TipAdvanced(_))),
            "reorg should surface a tip-advance event: {events:?}"
        );
    }

    #[test]
    fn accepted_tx_relays_to_other_peers() {
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        use avila_consensus::{script, transaction::Transaction};

        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        let mut cs = regtest();
        // 101 blocks so the h1 coinbase is mature for a mempool spend.
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        let (mut peer_b, _id_b) = add_peer(&mut mgr);
        handshake(&mut mgr, &mut peer_a, &mut cs);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        testpipe::drain(&mut peer_a, MAGIC);
        testpipe::drain(&mut peer_b, MAGIC);
        // The empty-headers reply ends both header phases.
        for p in [&mut peer_a, &mut peer_b] {
            testpipe::inject(p, MAGIC, &Message::Headers(vec![]));
        }
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_a, MAGIC);
        testpipe::drain(&mut peer_b, MAGIC);

        // A delivers a valid spend of the h1 coinbase (OP_1 outputs are
        // anyone-can-spend).
        let op = OutPoint {
            txid: blocks[0].transactions[0].txid(),
            vout: 0,
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: op,
                script_sig: Script::new(vec![]),
                sequence: 0xffff_ffff,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 4_999_000_000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let txid = tx.txid();
        testpipe::inject(&mut peer_a, MAGIC, &Message::Tx(tx));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        assert!(mgr.mempool().get(&txid).is_some(), "tx entered the pool");
        let sent_b = testpipe::drain(&mut peer_b, MAGIC);
        assert!(
            sent_b.iter().any(|m| matches!(
                m,
                Message::Inv(vs)
                    if vs.iter().any(|v| v.inv_type == crate::message::InvType::Tx
                        && v.hash.as_bytes() == txid.as_bytes())
            )),
            "B should get an inv for the tx: {sent_b:?}"
        );
        // The source peer is not re-announced its own tx.
        let sent_a = testpipe::drain(&mut peer_a, MAGIC);
        assert!(
            !sent_a.iter().any(|m| matches!(m, Message::Inv(vs)
                if vs.iter().any(|v| v.hash.as_bytes() == txid.as_bytes()))),
            "source peer must not hear its own tx back: {sent_a:?}"
        );
    }

    #[test]
    fn mempool_request_is_served_from_the_pool() {
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        use avila_consensus::{script, transaction::Transaction};

        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        handshake(&mut mgr, &mut peer_a, &mut cs);
        testpipe::drain(&mut peer_a, MAGIC);
        // Pool a tx, then answer the peer's `mempool` request.
        let op = OutPoint {
            txid: blocks[0].transactions[0].txid(),
            vout: 0,
        };
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: op,
                script_sig: Script::new(vec![]),
                sequence: 0xffff_ffff,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 4_999_000_000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let txid = tx.txid();
        mgr.mempool().accept_tx(tx, &cs, NOW).unwrap();
        testpipe::inject(&mut peer_a, MAGIC, &Message::Mempool);
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer_a, MAGIC);
        assert!(
            sent.iter().any(|m| matches!(
                m,
                Message::Inv(vs)
                    if vs.iter().any(|v| v.inv_type == crate::message::InvType::Tx
                        && v.hash.as_bytes() == txid.as_bytes())
            )),
            "mempool request should be answered with the pooled txid: {sent:?}"
        );
    }

    #[test]
    fn addr_gossip_fills_the_book() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);

        let gossip = vec![
            AddrEntry {
                time: NOW - 10,
                addr: addrman::net_addr_of("93.184.216.34:18444".parse().unwrap(), NODE_NETWORK),
            },
            AddrEntry {
                time: NOW - 5,
                addr: addrman::net_addr_of("93.184.216.35:18445".parse().unwrap(), NODE_NETWORK),
            },
        ];
        testpipe::inject(&mut peer, MAGIC, &Message::Addr(gossip));
        mgr.tick(&mut cs, NOW);
        assert_eq!(mgr.addr_book().len(), 2);
    }

    #[test]
    fn getaddr_serves_gossiped_peers() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);

        let gossip = vec![AddrEntry {
            time: NOW - 10,
            addr: addrman::net_addr_of("93.184.216.34:18444".parse().unwrap(), NODE_NETWORK),
        }];
        testpipe::inject(&mut peer, MAGIC, &Message::Addr(gossip));
        testpipe::inject(&mut peer, MAGIC, &Message::GetAddr);
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        match sent.iter().find(|m| matches!(m, Message::AddrV2(_))) {
            Some(Message::AddrV2(entries)) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].port, 18444);
                assert_eq!(entries[0].network, 1); // ipv4
            }
            _ => panic!("no addrv2 reply in {sent:?}"),
        }
    }

    /// Dead endpoints must never block the tick: dials run on worker
    /// threads bounded by the open-slot count, and completions drain
    /// on the next maintenance round. Closed localhost ports refuse
    /// instantly, so no real network is touched.
    #[test]
    fn maintain_outbounds_dials_are_bounded_workers() {
        let mut mgr = PeerManager::<TcpStream>::new(2);
        for p in 1u16..=3 {
            assert!(mgr.add_node(format!("127.0.0.1:{p}"), false));
        }

        // First round: two slots open → at most two workers queued,
        // and the call itself never waits on a connection timeout.
        let t0 = Instant::now();
        let dialed = mgr.maintain_outbounds(MAGIC, 0);
        assert!(t0.elapsed() < Duration::from_secs(1));
        assert_eq!(dialed.len(), 2);
        assert_eq!(mgr.pending_dials.len(), 2);
        assert_eq!(mgr.len(), 0);

        // Workers report refusal back on the channel; rounds drain
        // them — pending dials clear and refused connections never
        // become sessions. The 30s addnode backoff keeps the dead
        // entries from re-queueing meanwhile.
        let mut dialed = Vec::new();
        for _ in 0..40 {
            dialed = mgr.maintain_outbounds(MAGIC, 0);
            if mgr.pending_dials.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(dialed.is_empty());
        assert!(mgr.pending_dials.is_empty());
        assert_eq!(mgr.len(), 0);
    }

    /// Inbound accept: a v1 client opens with the `version` message —
    /// `accept_one` detects the prefix and leaves the bytes for the
    /// session's own decoder; a BIP324 client gets the responder
    /// handshake. Both land as inbound sessions via `accept_peer` +
    /// `drain_inbounds`.
    #[test]
    fn inbound_accepts_v1_and_v2_peers() {
        use std::io::Write;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let mut mgr = PeerManager::<TcpStream>::new(8);
        mgr.set_v2transport(true);

        // v1 peer: send a real version message in cleartext.
        let mut v1 = TcpStream::connect(laddr).unwrap();
        let version = peer_version(0);
        let frame = crate::codec::encode_frame(
            MAGIC,
            crate::codec::Command::new("version").unwrap(),
            &crate::message::Message::Version(version).encode(),
        );
        v1.write_all(&frame).unwrap();

        let (stream, remote) = listener.accept().unwrap();
        mgr.accept_peer(stream, remote, MAGIC, 0, 0);

        // v2 peer: run the initiator handshake over a real socket.
        let mut v2 = TcpStream::connect(laddr).unwrap();
        v2.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        v2.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let (stream2, remote2) = listener.accept().unwrap();
        mgr.accept_peer(stream2, remote2, MAGIC, 0, 0);
        // Drive the initiator handshake — the worker responds.
        let chan = match crate::bip324::handshake(&mut v2, MAGIC).unwrap() {
            crate::bip324::Handshake::V2(c, g) => crate::bip324::V2Channel::new(c, g),
            crate::bip324::Handshake::V1Fallback => panic!("responder fell back to v1"),
        };
        let mut v2_session = PeerSession::initiate_v2_channel(
            v2,
            MAGIC,
            peer_version(0),
            SEND_BUDGET_PER_PEER,
            chan,
        )
        .unwrap();
        let _ = v2_session.flush();

        // Both sessions land through drain_inbounds — each call
        // drains only what completed, so accumulate across polls.
        let mut admitted = Vec::new();
        for _ in 0..600 {
            admitted.extend(mgr.drain_inbounds());
            if admitted.len() == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(admitted.len(), 2);
        assert_eq!(mgr.len(), 2);
        for snap in mgr.peer_snapshots() {
            assert!(snap.inbound);
        }
        // The v2 session carries a session id; v1 reports none.
        let protocols: Vec<&str> = mgr
            .peer_snapshots()
            .iter()
            .map(|p| p.transport_protocol)
            .collect();
        assert!(protocols.contains(&"v2"));
        assert!(protocols.contains(&"v1"));
    }
    /// The scheduler: `run_due_tasks` fires jobs whose `next_run`
    /// passed on the mockable clock; `scheduler_forward` compresses
    /// time for `mockscheduler`.
    #[test]
    fn scheduler_runs_due_and_forwards() {
        use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
        static CLOCK: AtomicI64 = AtomicI64::new(1_700_000_000);
        static RAN: AtomicU64 = AtomicU64::new(0);
        fn now() -> i64 {
            CLOCK.load(Ordering::Relaxed)
        }
        let mut mgr = PeerManager::<testpipe::End>::new(4);
        mgr.set_clock(now);
        mgr.schedule_every("tick", 60, |_| {
            RAN.fetch_add(1, Ordering::Relaxed);
        });

        // Not due yet — 59s under the interval.
        CLOCK.store(1_700_000_059, Ordering::Relaxed);
        mgr.run_due_tasks();
        assert_eq!(RAN.load(Ordering::Relaxed), 0);

        // Due at +60s.
        CLOCK.store(1_700_000_060, Ordering::Relaxed);
        mgr.run_due_tasks();
        assert_eq!(RAN.load(Ordering::Relaxed), 1);

        // mockscheduler 3600 — forward fires it once (not 60×).
        mgr.scheduler_forward(3600);
        assert_eq!(RAN.load(Ordering::Relaxed), 2);
    }
}

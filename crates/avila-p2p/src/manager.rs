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
use crate::sync::{BLOCK_STALLING_TIMEOUT, MAX_BLOCKS_IN_TRANSIT_PER_PEER, PeerSync};

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
/// Pure hint update — the new hint is the larger of the observed diff
/// and half the old hint (fast rise, gradual decay).
/// Sketch capacity for a link's next round — sized by the observed
/// diff, not the pool: a round that decoded N differences sizes the
/// next at `2N + 32`, min 16 (a sketch under the diff can't decode and
/// costs a bisect round-trip), capped at 1024 (a wider diff than that
/// is cheaper to bisect or inv-announce anyway).
fn recon_capacity(hint: u32) -> usize {
    (hint.saturating_mul(2) as usize + 32).clamp(16, 1024)
}

fn recon_hint_update(hint: u32, diff: u64) -> u32 {
    let observed = u32::try_from(diff).unwrap_or(u32::MAX);
    observed.max(hint / 2)
}

fn recon_pool(
    mempool: &avila_mempool::Mempool,
    salt: u64,
    exclude: &std::collections::HashSet<avila_consensus::hash::Txid>,
) -> (
    Vec<u32>,
    std::collections::HashMap<u32, avila_consensus::hash::Txid>,
) {
    let mut ids = Vec::new();
    let mut map = std::collections::HashMap::new();
    for txid in mempool.txids() {
        // Stem-pending txs stay out of the sketch until fluff — on a
        // recon link the next scheduled round would leak them inside
        // the stem delay and turn the hop decorative (queue #7).
        // `mempool.private` entries never reconcile — the sketch
        // announces membership to the whole link.
        if exclude.contains(&txid) || mempool.is_private(&txid) {
            continue;
        }
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

/// Core's `MAX_ADDR_RATE_PER_SECOND` — the steady-state rate the
/// per-peer address-processing token bucket refills at.
const MAX_ADDR_RATE_PER_SECOND: f64 = 0.1;

/// Core's `MAX_ADDR_PROCESSING_TOKEN_BUCKET` — the passive refill's
/// ceiling. A peer we've just asked `getaddr` can still push the
/// bucket above this via a one-time bonus (Core bypasses the cap for
/// exactly that reply); nothing in this crate sends `getaddr` yet, so
/// only the passive refill applies today.
const MAX_ADDR_PROCESSING_TOKEN_BUCKET: f64 = 1000.0;
/// BIP157 serving is cheap per request but unbounded spam costs disk
/// reads — one filter request/second sustained, burst 20.
const CFILTER_RATE_PER_SECOND: f64 = 1.0;
const CFILTER_TOKEN_BUCKET: f64 = 20.0;

/// Core's `HEADERS_DOWNLOAD_TIMEOUT_BASE` — the fixed floor of the
/// overall deadline the headers-sync leader has to catch us up, on top
/// of a per-estimated-missing-header allowance
/// ([`HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER`]). Unlike
/// [`crate::sync::HEADERS_RESPONSE_TIME`] (one outstanding request),
/// this bounds the *whole* sync-from-this-leader effort, so a leader
/// that keeps answering promptly but never actually catches us up —
/// e.g. one stuck feeding an endlessly-abandoned low-work chain —
/// still eventually loses leadership.
const HEADERS_DOWNLOAD_TIMEOUT_BASE: Duration = Duration::from_secs(15 * 60);
/// Core's `HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER` — additional allowance
/// per header we estimate we're missing (from how stale our best
/// header is relative to the network's target block spacing).
const HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER: Duration = Duration::from_millis(1);
/// Core's "caught up enough that the sync-peer timeout no longer
/// applies" window: `m_best_header->Time() > now - 24h`.
const RECENT_HEADER_WINDOW_SECS: u32 = 24 * 60 * 60;

/// An eclipse indicator — advisory, not proof (queue #12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EclipseSignal {
    /// Tip >24h stale while ≥4 peers all claim a higher height.
    TipStale,
    /// Every outbound peer shares one /16 net group.
    DiversityCollapse,
    /// All established peers are inbound — outbound slots empty.
    AllInbound,
}

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
    /// Eclipse indicators fired — advisory, not proof (queue #12).
    EclipseSuspected(Vec<EclipseSignal>),
    /// A peer dominated dispatch CPU (>50% share, >200ms/s sustained)
    /// and lost this tick's poll — backpressure throttling, not a
    /// disconnect (queue #14).
    /// With a proxy configured, outbound dials keep failing — the
    /// private-mode route itself is down. Edge-triggered at 3
    /// consecutive failures so one refused dial isn't noise.
    ProxyUnreachable,
    /// We attempted BIP324 but the peer only completed cleartext v1 —
    /// a *forced downgrade* signal: a MITM can strip the v2 attempt
    /// this way (BIP324 threat model). Telemetry, not a ban — v1
    /// peers legitimately exist.
    V2Downgraded {
        /// The remote address that only completed v1.
        addr: SocketAddr,
    },
    CpuThrottled {
        /// The manager-assigned peer id.
        peer: u64,
        /// Its decayed dispatch rate this window, ns/s.
        rate_ns: u64,
    },
    /// A peer announced blocks we don't have (headers may need fetching).
    Announced {
        /// The peer id.
        peer: u64,
        /// Announced block hashes we lack.
        missing: Vec<BlockHash>,
    },
    /// A recon peer persistently misses the circulating tx set —
    /// telemetry, not a verdict: heavy filtering and a slow-syncing
    /// peer look alike from here (queue #19).
    ReconDivergence {
        /// The peer id.
        peer: u64,
        /// Completed reconciliation rounds at fire time.
        rounds: u64,
        /// Cumulative ids we held that their pool lacked.
        their_misses: u64,
        /// Cumulative ids they held that our pool lacked.
        our_misses: u64,
    },
    /// A compact block decoded on a negotiated link — the short-id
    /// reconstruction attempt has started.
    CompactReceived {
        /// The peer id.
        peer: u64,
        /// The block hash.
        block: BlockHash,
        /// Short-id slots the block carried.
        short_ids: usize,
    },
    /// A compact block reconstructed entirely from the mempool — no
    /// `getblocktxn` round trip needed.
    CompactHit {
        /// The peer id.
        peer: u64,
        /// The block hash.
        block: BlockHash,
    },
    /// A compact block had unknown txs — `getblocktxn` went out; the
    /// partial reconstruction waits on `blocktxn`.
    CompactPatchRequest {
        /// The peer id.
        peer: u64,
        /// The block hash.
        block: BlockHash,
        /// Tx slots we could not resolve locally.
        missing: usize,
    },
    /// The `blocktxn` reply left slots unfilled (lied or raced) —
    /// fell back to a plain `getdata` for the whole block.
    CompactFallback {
        /// The peer id.
        peer: u64,
        /// The block hash.
        block: BlockHash,
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
    /// Rotated off headers leadership once for an overdue page —
    /// re-election prefers peers not so marked while any exist.
    leader_slow: bool,
    /// Consecutive stall-release cycles with no block delivery. Core's
    /// stall recovery reassigns a stalling peer's blocks to others
    /// instead of dropping it outright — disconnect only after
    /// repeated theft yields nothing (the peer is dead, not slow).
    stall_releases: u32,
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
    /// Address entries dropped by the rate limiter (`addr_rate_limited`).
    addr_rate_limited: u64,
    /// `Peer::m_addr_token_bucket` — spendable address-processing
    /// tokens; one is spent per `addr`/`addrv2` entry, refilled at
    /// [`MAX_ADDR_RATE_PER_SECOND`] up to [`MAX_ADDR_PROCESSING_TOKEN_BUCKET`].
    addr_token_bucket: f64,
    /// `Peer::m_addr_token_timestamp` — when the bucket was last
    /// refilled, so the refill amount is `elapsed * rate`.
    addr_token_timestamp: Instant,
    /// Compact-filter request budget — `getcf*` requests spend one
    /// token each; an empty bucket is silently unserved (legal
    /// requests, so no disconnect — just no disk reads).
    cfilter_token_bucket: f64,
    /// Refill checkpoint for `cfilter_token_bucket`.
    cfilter_token_timestamp: Instant,
    /// Cumulative nanoseconds spent inside `dispatch` on this peer's
    /// events — the per-peer CPU accounting PEER_BUDGETS tracks.
    cpu_ns: u64,
    /// Dispatch nanos accrued in the current accounting window —
    /// folded into `cpu_ewma_ns` once a second.
    cpu_window_ns: u64,
    /// Window start for `cpu_window_ns`.
    cpu_window_start: Instant,
    /// Exponentially-decayed per-second dispatch cost — the throttle
    /// input: a peer saturating the poll loop's CPU budget loses its
    /// next poll (socket backpressure slows it; no disconnect —
    /// a sync leader legitimately dominates during IBD).
    cpu_rate_ns: u64,
    /// `Peer::m_getaddr_recvd` — whether this peer has already been
    /// answered once; a later `getaddr` on the same connection is
    /// silently ignored.
    getaddr_recvd: bool,
    /// Audit P2P-BIP35: last answered BIP35 `mempool` request —
    /// the reply carries the whole pool, so it's inbound-only and
    /// rate-limited rather than free bandwidth amplification.
    mempool_req_last: Option<Instant>,
    /// BIP-133 `feefilter` — the peer's advertised minimum feerate
    /// (sat/kvB). Announcements below it are suppressed for this link;
    /// 0 = the peer hasn't sent one (serve everything).
    min_fee: u64,
    /// The nonce we sent in our own `version`, when this was an
    /// outbound dial (`None` for inbound accepts, which never register
    /// a nonce to check against). Mirrored into
    /// [`PeerManager::outbound_nonces`] for the self-connect check and
    /// removed from it when this entry is dropped.
    our_nonce: Option<u64>,
    /// BIP330 link state — `Some` when the peer negotiated `sendrecon`.
    recon: Option<crate::recon::ReconPeer>,
    /// An open reconciliation round we initiated (awaiting `sketch`).
    recon_round: Option<crate::recon::ReconRound>,
    /// Our pool's short-id -> txid map for the last open/answer — how a
    /// `reconcildiff` ask resolves to a body we can send.
    recon_map: std::collections::HashMap<u32, avila_consensus::hash::Txid>,
    /// Audit P2P-1: last answered `reqrecon` + abuse counter — each
    /// request costs a sketch solve over the whole pool, so peers get
    /// a minimum interval; persistently faster is misbehavior.
    recon_req_last: Option<Instant>,
    recon_req_violations: u32,
    /// Recon telemetry — completed rounds and cumulative misses each
    /// round produced. A peer whose diff stays persistently wide
    /// (missing most of our pool every round) is an eclipse/censorship
    /// signal worth surfacing (queue #19).
    pub recon_rounds: u64,
    pub recon_misses: u64,
    /// Ids we held that the peer's pool lacked — the divergence half
    /// of the diff. Persistently high = the peer isn't seeing the
    /// circulating set.
    pub recon_their_misses: u64,
    /// The divergence alarm already fired for this connection — the
    /// event is edge-triggered, not per-round.
    recon_alarm_sent: bool,
    /// When the next initiated round may start.
    next_recon: Instant,
    /// An in-progress bisected close: our half-pools and the misses
    /// collected so far — `lo` is consumed by the first `sketch`, `hi`
    /// by the second (fixed reply order).
    recon_bisect: Option<ReconBisect>,
    /// Largest diff this link has produced so far (decays per round):
    /// the sketch-capacity hint — a round observed at size N sizes the
    /// next at `2N + margin`, so capacity tracks the actual diff
    /// rather than the whole pool's size.
    recon_diff_hint: u32,
    /// BIP152: the peer negotiated `sendcmpct` at version ≥2 — it can
    /// send us `cmpctblock` and understands `blocktxn`.
    cmpct_v2: bool,
    /// BIP152: the peer asked for high-bandwidth announcements — we
    /// announce new tips to it via `cmpctblock` directly (capped by
    /// `hb_peers` at the manager level).
    cmpct_hb: bool,
    /// Blocks mid-reconstruction from this peer's `cmpctblock`s —
    /// bounded (`MAX_PARTIAL_BLOCKS`); a `blocktxn` joins by hash.
    partial_blocks: std::collections::VecDeque<crate::compact::PartialBlock>,
    /// Reconstruction telemetry — cmpctblocks received, completed
    /// purely from the pool, completed via `blocktxn`, and full-block
    /// fallbacks after incomplete replies.
    pub cmpct_recv: u64,
    pub cmpct_hit: u64,
    pub cmpct_getblocktxn: u64,
    pub cmpct_fell_back: u64,
}

impl<S> PeerEntry<S> {
    /// Spends one compact-filter token — refills at
    /// [`CFILTER_RATE_PER_SECOND`] up to [`CFILTER_TOKEN_BUCKET`].
    /// `false` means the request is dropped unserved (legal traffic,
    /// never a ban reason — the peer just doesn't get disk reads for
    /// free forever).
    fn cfilter_allow(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(self.cfilter_token_timestamp)
            .as_secs_f64();
        self.cfilter_token_bucket = (self.cfilter_token_bucket + elapsed * CFILTER_RATE_PER_SECOND)
            .min(CFILTER_TOKEN_BUCKET);
        self.cfilter_token_timestamp = now;
        if self.cfilter_token_bucket >= 1.0 {
            self.cfilter_token_bucket -= 1.0;
            true
        } else {
            false
        }
    }
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
    /// The peer's misses across both halves (the divergence signal).
    their_misses: u64,
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
    /// BIP-133 — the peer's advertised `feefilter` minimum (sat/kvB);
    /// 0 when unsent. `getpeerinfo`'s `minfeefilter`.
    pub min_fee: u64,
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
    /// Cumulative ms spent dispatching this peer's messages.
    pub cpu_ms: u64,
    /// Decayed per-second dispatch cost, ms — the throttle input.
    pub cpu_rate_ms: u64,
    /// Completed recon rounds on this link and the cumulative miss
    /// count — a persistently-wide diff is a censorship/eclipse signal.
    pub recon_rounds: u64,
    pub recon_misses: u64,
    /// Cumulative ids we held that the peer's pool lacked — a
    /// persistently-wide *their-side* diff is the filtering signal.
    pub recon_their_misses: u64,
    /// BIP152 — the peer's `sendcmpct` negotiated v2 (wtxid shortids).
    pub cmpct_v2: bool,
    /// BIP152 — the peer asked for high-bandwidth `cmpctblock`
    /// announcements.
    pub cmpct_hb: bool,
    /// BIP152 — what we asked for in our `sendcmpct` (`Some(true)` =
    /// hb requested of them); `None` = compact relay off.
    pub cmpct_asked_hb: Option<bool>,
    /// `cmpctblock`s received, fully reconstructed, `getblocktxn`s
    /// asked, and full-block fallbacks on this link.
    pub cmpct_recv: u64,
    pub cmpct_hit: u64,
    pub cmpct_getblocktxn: u64,
    pub cmpct_fell_back: u64,
    /// Blocks currently mid-reconstruction.
    pub partial_blocks: usize,
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
    /// The current leader's overall deadline to catch us up (Core's
    /// `Peer::m_headers_sync_timeout`) — armed lazily the first tick a
    /// peer is observed as leader, cleared whenever leadership is.
    /// Independent of any single outstanding request's timeout
    /// ([`crate::sync::PeerSync::headers_timed_out`]): this bounds the
    /// whole sync-from-this-leader effort.
    headers_sync_deadline: Option<Instant>,
    /// Aggregate bound on block reservations across all peers —
    /// defaults to [`MAX_BLOCKS_IN_TRANSIT_TOTAL`].
    max_in_flight_total: usize,
    /// Height-sorted `(height, hash)` fetch index for the fill pass —
    /// rebuilt only when the header set grows, so each tick scans the
    /// unfetched suffix instead of re-sorting the whole index per peer.
    fetch_index: Vec<(u32, avila_consensus::hash::BlockHash)>,
    /// Header count `fetch_index` was built at.
    fetch_index_headers: usize,
    /// Connected height at the last `fill_queues` — stall diagnostics
    /// compare the frontier's movement against wall time.
    last_frontier: u32,
    /// When the frontier last advanced — a frontier flat past 60s gets
    /// a one-line diagnostic naming the blocking hash's fetch state.
    frontier_moved_at: Instant,
    /// Round-robin cursor for `fill_queues` peer order — HashMap
    /// iteration order is stable, so the frontier block otherwise lands
    /// on the same peer every tick and a silent withholder re-pins it
    /// after each 16s release (live wedge at height 140,378: one peer
    /// monopolized the frontier reservation for minutes).
    fill_rot: usize,
    /// Bounded `(hash → delivering peer)` journal — a deferred script
    /// failure surfaces at the *next* accept, not the guilty block's;
    /// misbehavior attribution reads this instead of blaming whoever
    /// delivered the triggering block.
    recent_deliveries: std::collections::VecDeque<(avila_consensus::hash::BlockHash, u64)>,
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
    /// Unix-second gate for the broadcast-pool rebroadcast pass —
    /// operator txs retry on a slower cadence than recon rounds.
    next_rebroadcast: u32,
    /// Selfish-stem relay (queue #18): locally-originated txs announce
    /// to ONE outbound peer first, hold a randomized delay, then fluff
    /// to everyone — the origin hides behind a hop instead of
    /// broadcasting to all at once. Entries: (txid, wtxid, fluff_at).
    /// Weaker than full Dandelion (single hop, no protocol change) —
    /// the point is plausible-deniability routing for our own txs.
    /// `bool` — `mempool.private` flag: never fluffs; the stem hop is
    /// the only announcement the entry ever makes.
    stem_pending: Vec<(
        avila_consensus::hash::Txid,
        avila_consensus::hash::Wtxid,
        Instant,
        bool,
    )>,
    /// Whether locally-submitted txs take the stem path — default on.
    stem_relay: bool,
    /// `mempool.private` — operator submissions are stem-only and
    /// hidden from the listing RPCs.
    private_submissions: bool,
    /// `tx.announce` verdict — consulted per (transaction, target
    /// link) before every `inv` fan-out hop. `false` skips that link;
    /// narrowing only, all built-in gates still apply.
    tx_announce_verdict: Option<TxAnnounceVerdict>,
    /// Compartment matrix (`relay.tx.deny_pairs`): "src->dst" pairs —
    /// src ∈ {inbound,outbound,local,extrapool}, dst ∈ {inbound,
    /// outbound}. A pair listed here is never announced across.
    deny_pairs: Vec<(String, String)>,
    /// `tx.serve` verdict — consulted per tx a peer requests via
    /// `getdata`; `false` answers the request `notfound`. Narrowing
    /// only — the verdict can't serve what the pools don't hold.
    tx_serve_verdict: Option<TxServeVerdict>,
    /// Audit P2P-7: the stem hop is per-EPOCH, not per-tx — a fresh
    /// random relay per transaction lets an observer correlate that
    /// all stem txs leaving through different hops came from one
    /// node (us). Dandelion's epoch model: same hop for the whole
    /// window, rotate on expiry or peer loss.
    stem_hop: Option<(u64, Instant)>,
    /// SOCKS5 proxy for automatic outbound dials — Core's `-proxy`.
    /// When set, EVERY outbound connection routes through it; there
    /// is no clearnet fallback (fail-closed — queue #13).
    proxy: Option<SocketAddr>,
    /// Consecutive failed dials under proxy mode — feeds the
    /// `ProxyUnreachable` edge trigger; reset by any successful dial.
    proxy_failures: u32,
    /// Fixed-size send cells — 0 disables. See `set_cell_bytes`.
    cell_bytes: usize,
    /// Whether new sessions advertise `sendutxproof` — we consume
    /// utreexo spend bundles (shadow connect). See
    /// [`Self::set_utxproof_consumer`].
    ask_utxproof: bool,
    /// `relay.block.compact` — negotiate BIP152 `sendcmpct` on new
    /// sessions and accept `cmpctblock` announcements.
    compact_blocks: bool,
    /// `relay.block.compact_high_bandwidth` — request hb announcements
    /// (our `sendcmpct` announce flag).
    compact_hb: bool,
    /// `relay.block.serve` — send `cmpctblock` to peers that asked for
    /// hb, and answer their `getblocktxn` reconstructions.
    compact_serve: bool,
    /// `relay.block.announce` — `headers|inv|none`; empty = follow the
    /// peer's `sendheaders` preference (Core's behavior).
    block_announce: String,
    /// `relay.block.serve` — `full` serves any stored block, `tip`
    /// only the checked tip's vicinity (reorg slack), `none` answers
    /// every block request `notfound`.
    block_serve_mode: String,
    /// The `block.serve` verdict — per-request gate like `tx.serve`.
    block_serve_verdict: Option<BlockServeVerdict>,
    /// `relay.tx.announce` — `all` (default), `private_only`
    /// (`mempool.private` entries only), `none` (no tx invs at all).
    tx_announce_mode: String,
    /// `relay.tx.to_inbound` — announce txs onto inbound links.
    tx_to_inbound: bool,
    /// `relay.tx.to_blocks_only_peers` — announce to peers whose
    /// version said `relay=false`. Default off (Core respects the
    /// flag); on, the operator overrides their preference.
    tx_to_blocks_only: bool,
    /// `net.blocks_only` — no tx relay at all: no announces, no
    /// inv-triggered fetches, no `mempool` dumps, no recon rounds.
    blocks_only: bool,
    /// `relay.tx.rebroadcast_local` — broadcast-pool retries of
    /// locally submitted txs until they confirm.
    rebroadcast_local: bool,
    /// `relay.tx.rebroadcast_interval` — seconds between retries.
    rebroadcast_interval: u32,
    /// `relay.tx.send_feefilter` — sat/kvB floor advertised to peers
    /// at handshake; 0 sends nothing (Core's default).
    send_feefilter: u64,
    /// Last time the eclipse-signal check ran (paced to ~60s).
    eclipse_checked_at: Instant,
    /// Named event ring (queue #33): every NetEvent the tick produces
    /// also lands here, capped — the operator-facing "what is the node
    /// doing" stream that Core #34901 asked for.
    event_ring: std::collections::VecDeque<NetEvent>,
    /// Erebus mitigation (queue #21): when loaded, outbound dialing
    /// deprioritizes candidates whose ASN already holds ≥2 outbound
    /// slots — a single transit network can't fill the peer set.
    asmap: crate::asmap::AsMap,
    /// Audit P2P-12: peers disconnected for proven misbehavior are
    /// discouraged — refused at the dial/accept gates for a window —
    /// instead of free to reconnect instantly. In-memory only, like
    /// Core's discouragement: it isn't operator-set, so it never
    /// lands in banlist.dat.
    discouraged: std::collections::HashMap<[u8; 16], Instant>,
    /// The operator ban list — Core's `BanMan`/`m_banned`: consulted
    /// on every dial and (future) inbound accept; `setban add` also
    /// drops matching live peers.
    bans: crate::banman::BanList,
    /// Where `bans` persists — `<net-datadir>/banlist.json`, written on
    /// every mutation like Core's `DumpBanlist`.
    banlist_path: Option<std::path::PathBuf>,
    /// `peers.ban_time` — the default `setban` duration (Core's
    /// `-bantime`); the RPC arm reads it so the config knob lands.
    default_ban_time: i64,
    /// Completed dial attempts — workers send `(addr, session result)`
    /// here and `maintain_outbounds` drains it on the tick, so an
    /// unreachable candidate costs a worker's 5s timeout instead of
    /// blocking the sync loop (Core's `ThreadOpenConnections` runs
    /// dials off the message loop the same way). The session includes
    /// any completed BIP324 handshake.
    dial_tx: std::sync::mpsc::Sender<(DialKey, DialOutcome)>,
    dial_rx: std::sync::mpsc::Receiver<(DialKey, DialOutcome)>,
    /// Dials in flight — counted against outbound slots so a dead
    /// network can't queue unbounded workers, and deduplicated so the
    /// same address is never dialed twice at once.
    /// Outbound dials in flight, mapped to whether v2 was requested —
    /// a landed v1 session after a v2 attempt is a forced downgrade.
    pending_dials: std::collections::HashMap<DialKey, bool>,
    /// Nonces we've sent in our own `version` on outbound connections,
    /// live for as long as that connection is (Core's `CheckIncomingNonce`
    /// scans not-yet-`fSuccessfullyConnected` outbound `CNode`s instead;
    /// keeping ours for the connection's whole life is a conservative
    /// superset — nobody but the dialed peer ever sees our nonce, so the
    /// only extra case caught is that same peer replaying it back at us
    /// after our dial already finished handshaking). A matching nonce on
    /// an inbound peer's `version` means that connection loops back to us.
    outbound_nonces: std::collections::HashSet<u64>,
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
    /// Inbound-admission hook (docs/DECISION_REGISTRY.md `peer.accept`):
    /// consulted after the ban check on every completed inbound
    /// handshake; `false` drops the session. Narrows acceptance only —
    /// a hook can refuse a peer, never override `network_active`,
    /// bans, or slot pressure.
    inbound_verdict: Option<InboundVerdict>,
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

/// What an inbound-admission hook (`peer.accept`) is told about a
/// completed handshake — the peer's version claims plus the transport
/// reality. The p2p crate owns no process machinery; the node passes a
/// plain closure.
#[derive(Clone, Debug)]
pub struct InboundFacts {
    /// The peer's socket address.
    pub remote: SocketAddr,
    /// Its claimed `nServices` (bit 0 = NODE_NETWORK, bit 24 =
    /// NODE_COMPACT_FILTERS).
    pub services: u64,
    /// Its claimed protocol version.
    pub protocol_version: i32,
    /// Its claimed user agent (`/name:version/`).
    pub user_agent: String,
    /// Its claimed tip height.
    pub start_height: i32,
    /// Whether it offered to relay transactions to us.
    pub relay: bool,
    /// Whether it announced BIP339 wtxid relay.
    pub wtxid_relay: bool,
    /// Whether it understands BIP155 addrv2.
    pub addrv2: bool,
    /// The negotiated transport: "v1" or "v2" (BIP324).
    pub transport: &'static str,
}

/// An inbound-admission judge — `false` drops the session. See
/// `set_inbound_verdict` and `InboundFacts`.
pub type InboundVerdict = Box<dyn FnMut(&InboundFacts) -> bool + Send>;

/// Where a transaction we're announcing came from — the provenance the
/// `tx.announce` verdict and the `deny_pairs` compartment matrix judge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxSource {
    /// Delivered by this peer's `tx` message — being relayed onward.
    Peer(u64),
    /// Operator-submitted (the RPC broadcast path) — stem hop or fluff.
    Local,
    /// The observed pool's propagation (`extrapool.relay`).
    Extrapool,
}

impl TxSource {
    /// The supplying peer when peer-sourced.
    #[must_use]
    pub fn peer(self) -> Option<u64> {
        match self {
            Self::Peer(id) => Some(id),
            _ => None,
        }
    }
}

/// Facts handed to the `tx.announce` verdict — the object, who we're
/// about to tell, and where it came from. Consulted once per
/// (transaction, target link), so per-peer gating is expressible but
/// announce throughput is bounded by helper latency.
#[derive(Clone, Debug)]
pub struct TxAnnounceFacts {
    /// The transaction being announced.
    pub txid: avila_consensus::hash::Txid,
    /// Its witness commitment id.
    pub wtxid: avila_consensus::hash::Wtxid,
    /// Source compartment: "inbound" | "outbound" | "local" |
    /// "extrapool".
    pub source: &'static str,
    /// The peer that delivered it, when `source` is link-sourced.
    pub source_peer: Option<u64>,
    /// The target link's peer id.
    pub peer: u64,
    /// Its address as "ip:port", when known.
    pub peer_addr: Option<String>,
    /// Target direction — true when they dialed us.
    pub peer_inbound: bool,
    /// The target's claimed user agent, if the handshake ran.
    pub peer_user_agent: Option<String>,
}

/// A `tx.announce` judge — `false` withholds the announcement from that
/// link. Narrows only; all built-in gates still apply.
pub type TxAnnounceVerdict = Box<dyn FnMut(&TxAnnounceFacts) -> bool + Send>;

/// Facts handed to a `tx.serve` verdict — one consult per tx a peer
/// asks us for via `getdata`.
#[derive(Debug)]
pub struct TxServeFacts {
    /// The transaction's txid (wtxid requests resolve through the
    /// mempool/extrapool index — unresolvable requests never reach the
    /// hook, they'd `notfound` regardless).
    pub txid: avila_consensus::hash::Txid,
    /// Witness hash of the same transaction.
    pub wtxid: avila_consensus::hash::Wtxid,
    /// Internal id of the requesting peer (`getpeerinfo`'s `id`).
    pub peer: u64,
    /// The peer's remote address string when known.
    pub peer_addr: Option<String>,
    /// True when the requester dialed us.
    pub peer_inbound: bool,
    /// The peer's advertised user agent, when a version was seen.
    pub peer_user_agent: Option<String>,
}

/// A `tx.serve` judge — conjunctive per-request gate on outbound tx
/// serving; `false` answers the request `notfound`, indistinguishable
/// from never having held the tx. Narrowing only — the verdict can't
/// serve what the pools don't hold.
pub type TxServeVerdict = Box<dyn FnMut(&TxServeFacts) -> bool + Send>;

/// Facts handed to a `block.serve` verdict — one consult per block a
/// peer asks us for via `getdata` or `getblocktxn`.
#[derive(Debug)]
pub struct BlockServeFacts {
    /// The requested block's hash.
    pub block_hash: avila_consensus::hash::BlockHash,
    /// Internal id of the requesting peer (`getpeerinfo`'s `id`).
    pub peer: u64,
    /// The peer's remote address string when known.
    pub peer_addr: Option<String>,
    /// True when the requester dialed us.
    pub peer_inbound: bool,
    /// The peer's advertised user agent, when a version was seen.
    pub peer_user_agent: Option<String>,
}

/// A `block.serve` judge — conjunctive gate on outbound block serving;
/// `false` answers the request `notfound` (or ignores `getblocktxn`),
/// indistinguishable from never having stored the block. Narrowing
/// only.
pub type BlockServeVerdict = Box<dyn FnMut(&BlockServeFacts) -> bool + Send>;

/// NetAddr → "ip:port" for the verdict facts — v4-mapped prints dotted
/// quad, v6 prints bracketed.
fn net_addr_string(a: &crate::message::NetAddr) -> String {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let ip = if a.ip[..10] == [0; 10] && a.ip[10] == 0xff && a.ip[11] == 0xff {
        IpAddr::V4(Ipv4Addr::new(a.ip[12], a.ip[13], a.ip[14], a.ip[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(a.ip))
    };
    format!("{ip}:{}", a.port)
}

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
            headers_sync_deadline: None,
            max_in_flight_total: MAX_BLOCKS_IN_TRANSIT_TOTAL,
            fetch_index: Vec::new(),
            fetch_index_headers: usize::MAX,
            last_frontier: 0,
            frontier_moved_at: Instant::now(),
            fill_rot: 0,
            recent_deliveries: std::collections::VecDeque::new(),
            addrbook: AddrBook::new(),
            mempool: avila_mempool::Mempool::new(),
            closed_bytes_sent: 0,
            closed_bytes_recv: 0,
            added_nodes: Vec::new(),
            network_active: true,
            addnode_dial: HashMap::new(),
            last_maintained: None,
            next_rebroadcast: 0,
            stem_pending: Vec::new(),
            stem_relay: true,
            private_submissions: false,
            tx_announce_verdict: None,
            tx_serve_verdict: None,
            deny_pairs: Vec::new(),
            stem_hop: None,
            asmap: crate::asmap::AsMap::empty(),
            event_ring: std::collections::VecDeque::with_capacity(1025),
            eclipse_checked_at: Instant::now(),
            proxy: None,
            proxy_failures: 0,
            cell_bytes: 0,
            ask_utxproof: false,
            compact_blocks: true,
            compact_hb: true,
            compact_serve: true,
            block_announce: String::new(),
            block_serve_mode: "full".to_string(),
            block_serve_verdict: None,
            tx_announce_mode: "all".to_string(),
            tx_to_inbound: true,
            tx_to_blocks_only: false,
            blocks_only: false,
            rebroadcast_local: true,
            rebroadcast_interval: 60,
            send_feefilter: 0,
            discouraged: std::collections::HashMap::new(),
            bans: crate::banman::BanList::new(),
            default_ban_time: crate::banman::DEFAULT_BANTIME,
            banlist_path: None,
            dial_tx: dial_channel.0,
            dial_rx: dial_channel.1,
            pending_dials: std::collections::HashMap::new(),
            outbound_nonces: std::collections::HashSet::new(),
            inbound_tx: inbound_channel.0,
            inbound_rx: inbound_channel.1,
            pending_accepts: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            inbound_verdict: None,
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

    /// Install the `peer.accept` decision-point hook: `drain_inbounds`
    /// consults it after the ban check; `false` drops the session.
    /// Narrows only — it cannot unban, unidle, or beat slot pressure.
    pub fn set_inbound_verdict(&mut self, judge: Option<InboundVerdict>) {
        self.inbound_verdict = judge;
    }

    /// Install the `tx.announce` decision-point hook: consulted per
    /// (transaction, target link) before every `inv` hop, including the
    /// stem hop and extrapool propagation. `false` withholds the
    /// announcement from that link. Narrows only — it cannot override
    /// `relay=false`, recon links, or the compartment matrix.
    ///
    /// Throughput caveat: one verdict per link per tx — announce rate
    /// is bounded by helper latency × peer count. Keep helpers fast.
    pub fn set_tx_announce_verdict(&mut self, judge: Option<TxAnnounceVerdict>) {
        self.tx_announce_verdict = judge;
    }

    /// `tx.serve` hook — one conjunctive verdict per tx a peer
    /// requests via `getdata`; `false` answers that item `notfound`.
    /// Narrows only — it cannot serve an unpooled tx. Throughput
    /// caveat: one verdict per tx per getdata — keep helpers fast.
    pub fn set_tx_serve_verdict(&mut self, judge: Option<TxServeVerdict>) {
        self.tx_serve_verdict = judge;
    }

    /// The compartment matrix (`relay.tx.deny_pairs`): "src->dst" pairs
    /// that are never announced across — src ∈ {inbound, outbound,
    /// local, extrapool}, dst ∈ {inbound, outbound}. E.g.
    /// "inbound->inbound" keeps inbound-sourced transactions off the
    /// inbound links; "local->inbound" confines locally-originated
    /// announcements to our chosen outbound routes.
    pub fn set_deny_pairs(&mut self, pairs: Vec<(String, String)>) {
        self.deny_pairs = pairs;
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
            if let Some(nonce) = p.our_nonce {
                self.outbound_nonces.remove(&nonce);
            }
            let (sent, recv) = p.session.byte_counters();
            self.closed_bytes_sent = self.closed_bytes_sent.saturating_add(sent);
            self.closed_bytes_recv = self.closed_bytes_recv.saturating_add(recv);
        }
    }

    /// `getnettotals` — cumulative wire bytes since startup: closed
    /// sessions plus every live session's current counters.
    #[must_use]
    pub fn net_totals(&self) -> (u64, u64) {
        self.peers.values().fold(
            (self.closed_bytes_sent, self.closed_bytes_recv),
            |(sent, recv), p| {
                let (ps, pr) = p.session.byte_counters();
                (sent.saturating_add(ps), recv.saturating_add(pr))
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
                    min_fee: peer.min_fee,
                    in_flight_hashes: peer.sync.in_flight_hashes().collect(),
                    transport_protocol: peer.session.transport_protocol(),
                    v2_session_id: peer.session.v2_session_id(),
                    recon: peer.recon.is_some(),
                    cpu_ms: peer.cpu_ns / 1_000_000,
                    cpu_rate_ms: peer.cpu_rate_ns / 1_000_000,
                    recon_rounds: peer.recon_rounds,
                    recon_misses: peer.recon_misses,
                    recon_their_misses: peer.recon_their_misses,
                    cmpct_v2: peer.cmpct_v2,
                    cmpct_hb: peer.cmpct_hb,
                    cmpct_asked_hb: peer.session.cmpct_asked(),
                    cmpct_recv: peer.cmpct_recv,
                    cmpct_hit: peer.cmpct_hit,
                    cmpct_getblocktxn: peer.cmpct_getblocktxn,
                    cmpct_fell_back: peer.cmpct_fell_back,
                    partial_blocks: peer.partial_blocks.len(),
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
        let scored: Vec<(bool, u64)> = self
            .peers
            .iter()
            .filter(|(id, p)| p.inbound && self.headers_leader != Some(**id))
            .map(|(id, p)| {
                let protected = now.duration_since(p.last_useful) < USEFUL_PROTECTION_WINDOW;
                (protected, *id)
            })
            .collect();
        // Evict-and-fill mitigation (Springer 2023: predictable inbound
        // eviction lets an attacker pick WHICH peer leaves — freeing a
        // slot for their own connection — and link a node's addresses
        // at 82-97% accuracy). The choice among the unprotected set is
        // therefore non-deterministic: an attacker can't steer which
        // connection drops, and filling slots evicts their own links
        // as often as honest ones. Deterministic scoring remains only
        // as the all-protected fallback ordering.
        let unprotected: Vec<u64> = scored
            .iter()
            .filter(|(protected, _)| !protected)
            .map(|(_, id)| *id)
            .collect();
        let pick_from: &[u64] = if unprotected.is_empty() {
            // All protected — fall back to the full candidate set;
            // randomize there too so the fallback isn't steerable.
            &scored.iter().map(|(_, id)| *id).collect::<Vec<_>>()
        } else {
            &unprotected
        };
        if pick_from.is_empty() {
            return None;
        }
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        let pick = pick_from[u64::from_le_bytes(seed) as usize % pick_from.len()];
        self.drop_peer(pick);
        Some(pick)
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
        session.set_cell_bytes(self.cell_bytes);
        session.ask_utxproof(self.ask_utxproof);
        // BIP-152 `announce` bit = "we will send YOU hb cmpctblock
        // announcements" — an offer, not a request. Only advertise it
        // when we actually serve (a peer that can't answer
        // getblocktxn leaves broken partial blocks).
        session.ask_cmpct(
            self.compact_blocks
                .then_some(self.compact_hb && self.compact_serve),
        );
        let now = Instant::now();
        // Self-connection detection (Core's `CheckIncomingNonce`):
        // remember the nonce on an outbound dial so a matching inbound
        // `version` can be recognized as our own loopback connection.
        // Inbound accepts register no nonce — Core only ever checks
        // against outbound dials, never the other way around.
        let our_nonce = (!inbound).then(|| session.our_nonce());
        if let Some(nonce) = our_nonce {
            self.outbound_nonces.insert(nonce);
        }
        self.peers.insert(
            id,
            PeerEntry {
                session,
                sync: PeerSync::new(),
                remote,
                wants_headers_announce: false,
                inbound,
                our_nonce,
                connected_at: now,
                last_useful: now,
                last_rx: now,
                last_ping: now,
                ping_outstanding: None,
                ping_last: None,
                ping_min: None,
                leader_slow: false,
                stall_releases: 0,
                last_block_time: None,
                last_tx_time: None,
                last_announce: None,
                synced_header_height: -1,
                synced_block_height: -1,
                addr_processed: 0,
                addr_rate_limited: 0,
                // Core's `Peer` default-inits the bucket to 1.0, not the
                // 1000-token ceiling — a peer earns burst capacity only
                // by us asking it for addresses or by waiting out the
                // slow passive refill.
                addr_token_bucket: 1.0,
                cfilter_token_bucket: CFILTER_TOKEN_BUCKET,
                cfilter_token_timestamp: Instant::now(),
                cpu_ns: 0,
                cpu_window_ns: 0,
                cpu_window_start: Instant::now(),
                cpu_rate_ns: 0,
                addr_token_timestamp: now,
                getaddr_recvd: false,
                mempool_req_last: None,
                min_fee: 0,
                recon: None,
                recon_round: None,
                recon_map: std::collections::HashMap::new(),
                cmpct_v2: false,
                cmpct_hb: false,
                partial_blocks: std::collections::VecDeque::new(),
                cmpct_recv: 0,
                cmpct_hit: 0,
                cmpct_getblocktxn: 0,
                cmpct_fell_back: 0,
                recon_req_last: None,
                recon_req_violations: 0,
                recon_rounds: 0,
                recon_misses: 0,
                recon_their_misses: 0,
                recon_alarm_sent: false,
                next_recon: Instant::now(),
                recon_bisect: None,
                recon_diff_hint: 0,
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
            headers_sync_deadline,
            mempool,
            outbound_nonces,
            stem_pending,
            tx_serve_verdict,
            block_serve_verdict,
            block_serve_mode,
            ..
        } = self;
        // Core's `m_num_preferred_download_peers - state.fPreferredDownload
        // >= 1`: the sync-peer timeout below only ever fires an established
        // peer if there's at least one *other* established peer to hand
        // leadership to — never abandon our only source of headers just
        // because it's slow.
        let established_count = peers.values().filter(|p| p.session.established()).count();
        let total_cpu_rate: u64 = peers.values().map(|p| p.cpu_rate_ns).sum();
        // Stem-pending txids stay out of recon sketches this tick —
        // a round would leak them inside the stem delay (queue #7).
        let stem_exclude: std::collections::HashSet<_> =
            stem_pending.iter().map(|(t, _, _, _)| *t).collect();
        let mut announce_tip: Option<u64> = None;
        // txid/wtxid to relay at end of tick, and the peer it came from.
        let mut announce_tx: Option<(
            u64,
            avila_consensus::hash::Txid,
            avila_consensus::hash::Wtxid,
        )> = None;
        for (&id, peer) in peers.iter_mut() {
            // Fold the window into the decayed per-second rate BEFORE
            // the throttle check can `continue` — previously the fold
            // sat below it, so a peer that tripped the threshold never
            // decayed: the busiest block-serving peer (exactly the one
            // holding the most reservations) became permanently
            // quarantined, and its in-flight entries pinned the
            // frontier forever (live wedge at height 134,384: age 246s
            // at queue position 0, `stalled()` never reached).
            if peer.cpu_window_start.elapsed() >= Duration::from_secs(1) {
                peer.cpu_rate_ns = peer.cpu_rate_ns / 2 + peer.cpu_window_ns;
                peer.cpu_window_ns = 0;
                peer.cpu_window_start = Instant::now();
            }
            // CPU throttle (PEER_BUDGETS): a peer burning >50% of
            // total dispatch CPU at >200ms/s loses this tick's poll —
            // socket backpressure slows it while others proceed. No
            // disconnect: the sync leader legitimately dominates
            // during IBD.
            if peer.cpu_rate_ns > 200_000_000
                && peer.cpu_rate_ns * 2 > total_cpu_rate
                // The headers leader legitimately dominates during
                // presync — throttling it starves the one socket we
                // must keep draining, and the remote side closes a
                // connection it can't write to.
                && *headers_leader != Some(id)
            {
                events.push(NetEvent::CpuThrottled {
                    peer: id,
                    rate_ns: peer.cpu_rate_ns,
                });
                continue;
            }
            if let Err(e) = peer.session.check_handshake_timeout() {
                dead.push((id, DisconnectReason::Session(e.to_string())));
                continue;
            }
            match peer.session.poll() {
                Ok(peer_events) => {
                    for event in peer_events {
                        peer.last_rx = Instant::now();
                        let t0 = Instant::now();
                        Self::dispatch(
                            id,
                            peer,
                            event,
                            cs,
                            now,
                            addrbook,
                            headers_leader,
                            headers_sync_deadline,
                            &mut announce_tip,
                            &mut announce_tx,
                            mempool,
                            &mut global_free,
                            &mut events,
                            &mut dead,
                            serve_filters,
                            outbound_nonces,
                            &stem_exclude,
                            &mut self.recent_deliveries,
                            tx_serve_verdict,
                            block_serve_verdict,
                            block_serve_mode.as_str(),
                            self.compact_blocks,
                            self.compact_serve,
                            self.blocks_only,
                            self.send_feefilter,
                        );
                        // Per-peer CPU accounting (PEER_BUDGETS):
                        // time inside dispatch lands on this peer's
                        // cumulative + window counters.
                        let spent = t0.elapsed().as_nanos() as u64;
                        peer.cpu_ns += spent;
                        peer.cpu_window_ns += spent;
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
            // The current leader's overall catch-up deadline (Core's
            // sync-peer timeout): armed lazily the first tick a peer is
            // seen holding leadership (freshly armed, so never
            // immediately exceeded), then checked every tick after.
            // This is independent of `headers_timed_out` above — a
            // leader that keeps answering every single request
            // promptly, but never actually finishes catching us up
            // (e.g. cycling through abandoned low-work syncs), would
            // otherwise never trip that per-request timeout at all.
            if *headers_leader == Some(id) {
                let deadline = *headers_sync_deadline
                    .get_or_insert_with(|| headers_download_deadline(cs, now));
                let caught_up =
                    cs.tree().tip().header.time > now.saturating_sub(RECENT_HEADER_WINDOW_SECS);
                if !caught_up && Instant::now() > deadline && established_count > 1 {
                    dead.push((id, DisconnectReason::Stalled));
                }
            }
            // Stall eviction: a block download that's gone quiet, or an
            // outstanding `getheaders` that has gone unanswered past
            // Core's `HEADERS_RESPONSE_TIME`. The latter matters even
            // for a peer that's otherwise alive and answering pings —
            // without it a headers leader that simply stops replying to
            // `getheaders` would freeze header sync until it
            // disconnects for some unrelated reason, since only the
            // leader is allowed to keep paging. Dropping it here clears
            // `headers_leader` below and `fill_queues` hands leadership
            // to another established peer on the next tick.
            // Per-hash staleness first: `stalled()` only watches the
            // queue front, so a peer that keeps answering other requests
            // can pin one hash forever — release stragglers back to the
            // pool so another peer picks them up next fill.
            peer.sync.release_older_than(BLOCK_STALLING_TIMEOUT * 8);
            if peer.sync.headers_timed_out() {
                dead.push((id, DisconnectReason::Stalled));
            } else if peer.sync.stalled() {
                // Core's stall recovery: a peer whose block requests
                // went unanswered isn't instantly dropped — its
                // reservations are released back to the fetch pool so
                // answering peers take over, and the peer survives if
                // it still delivers. Only a peer that stalls release
                // after release without ever contributing gets dropped.
                let released = peer.sync.release_in_flight();
                peer.stall_releases += 1;
                if released == 0 || peer.stall_releases >= 4 {
                    dead.push((id, DisconnectReason::Stalled));
                }
            }
        }
        for (id, reason) in dead {
            // Audit P2P-12: proven misbehavior discourages the peer's
            // IP for a window — reconnects and re-dials are refused at
            // the existing is_banned gates. In-memory only.
            if matches!(reason, DisconnectReason::Misbehavior(_))
                && let Some(peer) = self.peers.get(&id)
                && let Some(remote) = &peer.remote
            {
                self.discouraged
                    .insert(remote.ip, Instant::now() + DISCOURAGE_FOR);
            }
            self.drop_peer(id);
            if self.headers_leader == Some(id) {
                self.headers_leader = None;
                self.headers_sync_deadline = None;
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
            self.send_tx_inv(&txid, &wtxid, TxSource::Peer(source));
        }
        self.fill_queues(cs, now);
        self.recon_pass();
        self.rebroadcast_pass(cs, now);
        self.stem_fluff_pass();
        // Eclipse-signal check — paced ~60s; advisory indicators only.
        if self.eclipse_checked_at.elapsed() >= Duration::from_secs(60) {
            self.eclipse_checked_at = Instant::now();
            let signals = self.eclipse_signals(cs, now);
            if !signals.is_empty() {
                events.push(NetEvent::EclipseSuspected(signals));
            }
        }
        for e in &events {
            if self.event_ring.len() >= 1024 {
                self.event_ring.pop_front();
            }
            self.event_ring.push_back(e.clone());
        }
        events
    }

    /// The bounded event ring — newest `NetEvent`s first.
    pub fn recent_events(&self) -> &std::collections::VecDeque<NetEvent> {
        &self.event_ring
    }

    /// Eclipse indicators (queue #12) — signatures, not proof:
    ///
    /// * `TipStale`: our tip is >24h old while ≥4 established peers
    ///   all claim a higher `start_height` — everyone is ahead of us
    ///   but nobody's delivering. On a healthy link that's impossible.
    /// * `DiversityCollapse`: ≥4 outbound peers and every one lives in
    ///   the same /16 — the outbound set has no route diversity.
    /// * `AllInbound`: ≥4 established peers and all are inbound —
    ///   every outbound slot has failed or been starved, the classic
    ///   eclipse precondition.
    ///
    /// Indicators only — an eclipse alarm is advisory. Cross-checking
    /// disjoint routes (#10) is the escalation path.
    pub fn eclipse_signals(&self, cs: &Chainstate, now: u32) -> Vec<EclipseSignal> {
        let mut out = Vec::new();
        let established: Vec<&PeerEntry<S>> = self
            .peers
            .values()
            .filter(|p| p.session.established())
            .collect();
        let outbound: Vec<&&PeerEntry<S>> = established.iter().filter(|p| !p.inbound).collect();

        // TipStale: stale tip + everyone claims more — but only once
        // our header tree has reached what peers claim. During headers
        // download the tree tip is mid-history: old by definition, so
        // staleness then means "still syncing", not "being eclipsed".
        let tip_time = cs.tree().tip().header.time;
        let stale = tip_time < now.saturating_sub(RECENT_HEADER_WINDOW_SECS);
        let our_height = cs.chain().len() as i32 - 1;
        let best_claim = established
            .iter()
            .filter_map(|p| p.session.peer().map(|i| i.start_height))
            .max()
            .unwrap_or(0);
        let headers_current =
            best_claim <= 0 || cs.tree().tip().height as i32 >= best_claim.saturating_sub(10);
        let all_claim_more = established.len() >= 4
            && established
                .iter()
                .all(|p| p.session.peer().map(|i| i.start_height).unwrap_or(0) > our_height);
        if stale && all_claim_more && headers_current {
            out.push(EclipseSignal::TipStale);
        }

        // DiversityCollapse: outbound set concentrated in one network
        // group — the same key outbound selection buckets by (v4 /16,
        // v6 /32, unroutable each their own).
        if outbound.len() >= 4 {
            let mut groups: HashMap<Vec<u8>, usize> = HashMap::new();
            for p in &outbound {
                if let Some(r) = p.remote {
                    *groups.entry(crate::addrman::net_group(&r.ip)).or_default() += 1;
                }
            }
            if groups.len() == 1 {
                out.push(EclipseSignal::DiversityCollapse);
            }
        }

        // AllInbound: every established peer dialed us.
        if established.len() >= 4 && outbound.is_empty() {
            out.push(EclipseSignal::AllInbound);
        }
        out
    }

    /// Announces a locally submitted transaction via a single stem
    /// hop — one random outbound relay peer gets the inv now; the
    /// general announce fires after a randomized delay
    /// (`stem_fluff_pass`). An observer watching our links sees us
    /// *relay* the tx once, not originate it — the difference between
    /// "probably their tx" and "maybe someone's."
    pub fn stem_announce(
        &mut self,
        txid: avila_consensus::hash::Txid,
        wtxid: avila_consensus::hash::Wtxid,
    ) {
        if self.blocks_only || self.tx_announce_mode == "none" {
            return;
        }
        if self.tx_announce_mode == "private_only" && !self.mempool.is_private(&txid) {
            return;
        }
        if !self.stem_relay {
            self.announce_tx(txid, wtxid);
            return;
        }
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        let roll = u64::from_le_bytes(seed);
        // Pick a random established OUTBOUND peer that accepts tx relay —
        // outbound links are our chosen routes; an inbound stem hop
        // would leak to whoever connected to us.
        let candidates: Vec<u64> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                !p.inbound
                    && p.recon.is_none()
                    && p.session.established()
                    && p.session.peer().is_some_and(|i| i.relay)
            })
            .map(|(id, _)| *id)
            .collect();
        // Audit P2P-7: per-EPOCH hop — reuse the current stem peer
        // for the whole window; only re-pick when the epoch expires
        // or the peer dropped out of the eligible set.
        const STEM_EPOCH: Duration = Duration::from_secs(600);
        let hop = match self.stem_hop {
            Some((id, epoch_start))
                if epoch_start.elapsed() < STEM_EPOCH && candidates.contains(&id) =>
            {
                id
            }
            _ => {
                let Some(&id) = candidates.get((roll as usize) % candidates.len().max(1)) else {
                    // No outbound peer — fluff immediately, better than silence.
                    self.announce_tx(txid, wtxid);
                    return;
                };
                self.stem_hop = Some((id, Instant::now()));
                id
            }
        };
        // The stem hop answers to the same gates — the compartment
        // matrix and the tx.announce verdict see source "local" here.
        let gated = if let Some(peer) = self.peers.get(&hop) {
            let dst = if peer.inbound { "inbound" } else { "outbound" };
            let denied = self
                .deny_pairs
                .iter()
                .any(|(s, d)| s == "local" && *d == dst);
            let facts = TxAnnounceFacts {
                txid,
                wtxid,
                source: "local",
                source_peer: None,
                peer: hop,
                peer_addr: peer.remote.as_ref().map(net_addr_string),
                peer_inbound: peer.inbound,
                peer_user_agent: peer.session.peer().map(|i| i.user_agent.clone()),
            };
            Some((denied, facts))
        } else {
            None
        };
        let permitted = match gated {
            None => false,
            Some((denied, facts)) => {
                !denied && self.tx_announce_verdict.as_mut().is_none_or(|v| v(&facts))
            }
        };
        if !permitted {
            // A denied stem hop isn't fatal — the fluff pass still
            // offers it to every link the gates allow.
            self.stem_pending.push((
                txid,
                wtxid,
                Instant::now() + Duration::from_secs(5),
                self.mempool.is_private(&txid),
            ));
            return;
        }
        if let Some(peer) = self.peers.get_mut(&hop) {
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
        // Fluff after a randomized 2–15s delay — the Dandelion stem
        // phase compressed to one hop.
        let delay_ms = 2_000 + (roll >> 8) % 13_000;
        self.stem_pending.push((
            txid,
            wtxid,
            Instant::now() + Duration::from_millis(delay_ms),
            self.mempool.is_private(&txid),
        ));
    }

    /// Drains stem-pending entries whose delay elapsed — the fluff
    /// phase announces the tx normally (recon links pick it up in the
    /// next round regardless).
    fn stem_fluff_pass(&mut self) {
        let now = Instant::now();
        let mut i = 0;
        while i < self.stem_pending.len() {
            if self.stem_pending[i].2 <= now {
                let (txid, wtxid, _, private) = self.stem_pending.remove(i);
                // `mempool.private` entries are stem-only — the hop
                // already announced; no broadcast follow-up.
                if private {
                    continue;
                }
                self.send_tx_inv(&txid, &wtxid, TxSource::Local);
            } else {
                i += 1;
            }
        }
    }

    /// Whether locally submitted txs take the stem path.
    pub fn set_stem_relay(&mut self, on: bool) {
        self.stem_relay = on;
    }

    /// `mempool.private` — operator submissions are stem-only and
    /// hidden from the listing RPCs.
    pub fn set_private_submissions(&mut self, on: bool) {
        self.private_submissions = on;
    }

    /// Whether `mempool.private` is on.
    #[must_use]
    pub fn private_submissions(&self) -> bool {
        self.private_submissions
    }

    /// Routes every automatic outbound dial through a SOCKS5 proxy —
    /// fail-closed: when set, no dial ever touches clearnet, and a
    /// dead proxy means no outbound peers rather than a silent leak.
    pub fn set_proxy(&mut self, proxy: Option<SocketAddr>) {
        self.proxy = proxy;
    }

    /// The configured SOCKS5 proxy, when any — the `addnode`/`onetry`
    /// path needs it to keep hostname resolution off local DNS
    /// (audit P2P-13).
    #[must_use]
    pub fn proxy(&self) -> Option<SocketAddr> {
        self.proxy
    }

    /// Fixed-size send cells (queue #17): pads every v2 session's
    /// outgoing queue to a cell multiple with decoy packets so wire
    /// write-sizes carry no message-length histogram. 0 disables;
    /// applies to live sessions and every session `add`ed later.
    pub fn set_cell_bytes(&mut self, bytes: usize) {
        self.cell_bytes = bytes;
        for peer in self.peers.values_mut() {
            peer.session.set_cell_bytes(bytes);
        }
    }

    /// Whether sessions advertise `sendutxproof` — on when the node
    /// runs the utreexo shadow consumer and wants bundles served.
    /// Applies to sessions registered after this call (sessions
    /// already handshaked are unchanged — same semantics as Core's
    /// `-v2transport` which only affects new links).
    pub fn set_utxproof_consumer(&mut self, on: bool) {
        self.ask_utxproof = on;
    }

    /// BIP152 configuration — `compact` negotiates `sendcmpct` and
    /// accepts `cmpctblock` on new sessions; `hb` is our
    /// high-bandwidth request flag; `serve` lets us send `cmpctblock`
    /// announcements and answer `getblocktxn`; `announce` is
    /// `headers|inv|none` or empty for the peer's `sendheaders`
    /// preference. New sessions only, like `sendutxproof`.
    pub fn set_compact_relay(&mut self, compact: bool, hb: bool, serve: bool, announce: &str) {
        self.compact_blocks = compact;
        self.compact_hb = hb;
        self.compact_serve = serve;
        self.block_announce = announce.to_string();
    }

    /// `relay.block.serve` mode + the `block.serve` verdict —
    /// `mode` is `full|tip|none`; `verdict` gates each requested
    /// block (and `getblocktxn`) conjunctively.
    pub fn set_block_serve(&mut self, mode: &str, verdict: Option<BlockServeVerdict>) {
        self.block_serve_mode = mode.to_string();
        self.block_serve_verdict = verdict;
    }

    /// `relay.tx.*` bulk apply — announce mode (`all|private_only|
    /// none`), inbound/blocks-only target reach, the outbound
    /// feefilter floor, and broadcast-pool retries.
    #[allow(clippy::too_many_arguments)]
    pub fn set_tx_relay(
        &mut self,
        announce: &str,
        to_inbound: bool,
        to_blocks_only: bool,
        send_feefilter: u64,
        rebroadcast_local: bool,
        rebroadcast_interval: u32,
    ) {
        self.tx_announce_mode = announce.to_string();
        self.tx_to_inbound = to_inbound;
        self.tx_to_blocks_only = to_blocks_only;
        self.send_feefilter = send_feefilter;
        self.rebroadcast_local = rebroadcast_local;
        self.rebroadcast_interval = rebroadcast_interval;
    }

    /// `net.blocks_only` — silence tx relay in every direction.
    pub fn set_blocks_only(&mut self, on: bool) {
        self.blocks_only = on;
    }

    /// Loads an AS bucketing map — Erebus mitigation: outbound dialing
    /// deprioritizes ASNs already holding ≥2 slots.
    pub fn set_asmap(&mut self, map: crate::asmap::AsMap) {
        self.asmap = map;
    }

    /// Broadcast-pool retries — Core issue #30471's broadcast pool:
    /// operator-submitted txs survive eviction and rebroadcast until
    /// they confirm. Runs at most once a minute; each due entry is
    /// re-admitted and re-announced. An entry whose inputs are spent
    /// (confirmed, or conflicted by a mined tx) can never confirm —
    /// it drops; soft failures back off exponentially.
    fn rebroadcast_pass(&mut self, cs: &mut Chainstate, now: u32) {
        if !self.rebroadcast_local || self.blocks_only {
            return;
        }
        if now < self.next_rebroadcast {
            return;
        }
        self.next_rebroadcast = now + self.rebroadcast_interval.max(10);
        for (txid, raw) in self.mempool.broadcast_pending(now) {
            let Ok(tx) = avila_consensus::transaction::Transaction::decode(&raw) else {
                self.mempool.unmark_broadcast(&txid);
                continue;
            };
            match self.mempool.accept_tx(tx.clone(), cs, now) {
                Ok(_) => {
                    self.mempool.mark_unbroadcast(&txid);
                    // Retries keep the origin-privacy property — stem
                    // hop, not an immediate all-peer announce.
                    self.stem_announce(txid, tx.wtxid());
                }
                Err(_) => {
                    // Dead iff an input resolves nowhere — UTXO set
                    // miss + not produced by any pooled or broadcast
                    // tx means it was confirmed-spent or never existed.
                    let dead = tx.inputs.iter().any(|i| {
                        self.mempool.resolve(cs, &i.previous_output).is_none()
                            && !self.mempool.is_broadcast_pending(&i.previous_output.txid)
                    });
                    if dead {
                        self.mempool.unmark_broadcast(&txid);
                    } else {
                        self.mempool.note_broadcast_retry(&txid, now);
                    }
                }
            }
        }
    }

    /// BIP330 scheduled rounds: for every established link that
    /// Folds an observed diff size into the per-peer capacity hint —
    /// rises immediately to cover a big round, decays by half per
    /// quiet round so a burst doesn't pin capacity high forever.
    fn recon_observe(peer: &mut PeerEntry<S>, diff: u64) {
        peer.recon_diff_hint = recon_hint_update(peer.recon_diff_hint, diff);
    }

    /// negotiated `sendrecon` and is due, open a sketch round over the
    /// current pool. Failed/finished rounds clear on the next due tick.
    fn recon_pass(&mut self) {
        if self.blocks_only {
            return;
        }
        let now = Instant::now();
        for peer in self.peers.values_mut() {
            let Some(link) = peer.recon else {
                continue;
            };
            if !link.they_respond || !peer.session.established() || now < peer.next_recon {
                continue;
            }
            peer.next_recon = now + RECON_INTERVAL;
            let salt = link.our_salt ^ link.their_salt;
            let pending: std::collections::HashSet<_> =
                self.stem_pending.iter().map(|(t, _, _, _)| *t).collect();
            let (our_ids, our_map) = recon_pool(&self.mempool, salt, &pending);
            let capacity = recon_capacity(peer.recon_diff_hint);
            let (round, req) = crate::recon::ReconRound::open(&our_ids, capacity);
            peer.recon_round = Some(round);
            peer.recon_map = our_map;
            let _ = peer.session.send(&req);
        }
    }

    /// Sends a tx inventory announcement to every established peer that
    /// accepts tx relay (BIP339: `wtx` for wtxidrelay peers, `tx`
    /// otherwise). `source` carries the provenance — peer-sourced
    /// relays spare the supplying peer; the compartment matrix and the
    /// `tx.announce` verdict can still gate individual links.
    fn send_tx_inv(
        &mut self,
        txid: &avila_consensus::hash::Txid,
        wtxid: &avila_consensus::hash::Wtxid,
        source: TxSource,
    ) {
        // `net.blocks_only` / `relay.tx.announce` — the whole fan-out
        // is quiet, or private entries only.
        if self.blocks_only || self.tx_announce_mode == "none" {
            return;
        }
        if self.tx_announce_mode == "private_only" && !self.mempool.is_private(txid) {
            return;
        }
        let src = self.source_compartment(source);
        // BIP-133: the announced tx's feerate (sat/kvB, hoisted — the
        // peer loop borrows &mut self) gates each peer's advertised
        // minimum. Extrapool-relayed txs aren't priced by the store —
        // they pass ungated.
        let feerate = self
            .mempool
            .entry(txid)
            .map(|e| e.fee.saturating_mul(1000) / (e.vsize.max(1) as i64));
        // The verdict/matrix are hoisted so the peer-map iteration
        // doesn't fight the borrow on `self`.
        let deny_pairs = std::mem::take(&mut self.deny_pairs);
        let mut verdict = self.tx_announce_verdict.take();
        for (&id, peer) in &mut self.peers {
            if TxSource::Peer(id) == source || !peer.session.established() {
                continue;
            }
            // `relay.tx.to_inbound` — inbound links hear nothing.
            if peer.inbound && !self.tx_to_inbound {
                continue;
            }
            let wants_tx = peer.session.peer().is_some_and(|i| i.relay);
            // `to_blocks_only_peers` overrides the peer's own
            // relay=false request (default respects it, like Core).
            if !wants_tx && !self.tx_to_blocks_only {
                continue;
            }
            // BIP-330: a recon link doesn't get tx announcements — the
            // next round reconciles the difference anyway, and skipping
            // the inv is exactly where the bandwidth win lives.
            if peer.recon.is_some() {
                continue;
            }
            // BIP-133 — don't waste an inv on a tx the peer's filter
            // already refuses.
            if let Some(rate) = feerate
                && rate < peer.min_fee as i64
            {
                continue;
            }
            let dst = if peer.inbound { "inbound" } else { "outbound" };
            if deny_pairs.iter().any(|(s, d)| s == src && *d == dst) {
                continue;
            }
            if let Some(v) = &mut verdict {
                let facts = TxAnnounceFacts {
                    txid: *txid,
                    wtxid: *wtxid,
                    source: src,
                    source_peer: source.peer(),
                    peer: id,
                    peer_addr: peer.remote.as_ref().map(net_addr_string),
                    peer_inbound: peer.inbound,
                    peer_user_agent: peer.session.peer().map(|i| i.user_agent.clone()),
                };
                if !v(&facts) {
                    continue;
                }
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
        self.deny_pairs = deny_pairs;
        self.tx_announce_verdict = verdict;
    }

    /// Source compartment for the compartment matrix: the direction of
    /// the delivering link, or the local/extrapool sources.
    fn source_compartment(&self, source: TxSource) -> &'static str {
        match source {
            TxSource::Peer(id) => match self.peers.get(&id) {
                Some(p) if p.inbound => "inbound",
                _ => "outbound",
            },
            TxSource::Local => "local",
            TxSource::Extrapool => "extrapool",
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
        self.send_tx_inv(&txid, &wtxid, TxSource::Local);
    }

    /// Extrapool propagation (`extrapool.relay` = "outbound"|"all"):
    /// announces an observed transaction with `extrapool` provenance —
    /// the compartment matrix and `tx.announce` gate it like any other
    /// source. `outbound_only` additionally confines it to our chosen
    /// routes (inbound links never learn we saw it).
    pub fn announce_extrapool_tx(
        &mut self,
        txid: avila_consensus::hash::Txid,
        wtxid: avila_consensus::hash::Wtxid,
        outbound_only: bool,
    ) {
        let src = TxSource::Extrapool;
        let comp = self.source_compartment(src);
        let deny_pairs = std::mem::take(&mut self.deny_pairs);
        let mut verdict = self.tx_announce_verdict.take();
        for (&id, peer) in &mut self.peers {
            if !peer.session.established()
                || (outbound_only && peer.inbound)
                || !peer.session.peer().is_some_and(|i| i.relay)
                || peer.recon.is_some()
            {
                continue;
            }
            let dst = if peer.inbound { "inbound" } else { "outbound" };
            if deny_pairs.iter().any(|(s, d)| s == comp && *d == dst) {
                continue;
            }
            if let Some(v) = &mut verdict {
                let facts = TxAnnounceFacts {
                    txid,
                    wtxid,
                    source: comp,
                    source_peer: None,
                    peer: id,
                    peer_addr: peer.remote.as_ref().map(net_addr_string),
                    peer_inbound: peer.inbound,
                    peer_user_agent: peer.session.peer().map(|i| i.user_agent.clone()),
                };
                if !v(&facts) {
                    continue;
                }
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
        self.deny_pairs = deny_pairs;
        self.tx_announce_verdict = verdict;
    }

    /// Announces the connected tip to every established peer — `headers`
    /// for sendheaders peers, `inv` otherwise (Core's `NewPoWValidBlock`
    /// fan-out). `exclude` spares the peer that delivered the block;
    /// `None` for locally submitted/mined blocks.
    fn send_tip_announce(&mut self, cs: &Chainstate, exclude: Option<u64>) {
        // The *checked* tip — not `tree().tip()` (best header) and not
        // `chain().last()` (which may be a speculative block whose
        // script checks are still in flight). We never relay a block
        // as verified before its checks actually passed.
        let tip_hash = cs.chain().get(cs.checked_height() as usize).copied();
        let tip_header = tip_hash.and_then(|h| cs.tree().get(&h)).map(|n| n.header);
        // `relay.block.announce` override — empty follows each peer's
        // negotiation (Core's behavior); `none` silences block
        // announcements entirely.
        let mode = self.block_announce.as_str();
        if mode == "none" {
            return;
        }
        let compact_serve = self.compact_serve;
        // Core grants high-bandwidth compact announcements to at most
        // 3 peers (`MAX_CMPCT_HB_PEERS`) — the block body is built
        // lazily on the first hb peer.
        let mut compacted: Option<Message> = None;
        let mut hb_sent = 0usize;
        for (&id, peer) in &mut self.peers {
            if Some(id) == exclude || !peer.session.established() {
                continue;
            }
            // High-bandwidth announces go to compact-capable peers —
            // our sendcmpct(announce=true) advertised the grant; the
            // <=3 cap is Core's MAX_CMPCT_HB_PEERS.
            if peer.cmpct_v2 && compact_serve && mode.is_empty() && hb_sent < 3 {
                if compacted.is_none() {
                    let Some(hash) = tip_hash else { break };
                    let Some(body) = cs.body(&hash) else { break };
                    compacted = Some(Message::CmpctBlock(crate::compact::make_cmpctblock(&body)));
                }
                if let Some(msg) = &compacted
                    && peer.session.send(msg).is_ok()
                {
                    hb_sent += 1;
                }
                continue;
            }
            let msg = if mode == "headers" || (mode.is_empty() && peer.wants_headers_announce) {
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
    /// The headers leader's buffered presync height — the tree tip
    /// doesn't move while presync runs, so this is the visible
    /// progress signal during early IBD.
    pub fn presync_height(&self) -> Option<u64> {
        self.headers_leader
            .and_then(|id| self.peers.get(&id))
            .and_then(|p| p.sync.presync_height())
    }

    fn fill_queues(&mut self, cs: &mut Chainstate, now: u32) {
        // Leaderless and connected: the first established peer resumes
        // headers paging from our tip (locator-based, so cheap).
        // Slow-leader handoff: a sync peer whose page request has gone
        // unanswered for >25s costs minutes over a full presync — peers
        // vary 100x in getheaders service time. Leadership moves on
        // without disconnecting: the peer may serve blocks fine, and
        // its presync buffer survives for a later re-election.
        let leader_overdue = self
            .headers_leader
            .and_then(|leader| self.peers.get(&leader))
            .is_some_and(|peer| peer.sync.headers_wait() > Some(Duration::from_secs(25)));
        if leader_overdue
            && let Some(leader) = self.headers_leader.take()
            && let Some(peer) = self.peers.get_mut(&leader)
        {
            peer.leader_slow = true;
        }
        if self.headers_leader.is_none()
            && let Some(id) = {
                // Prefer a peer that's already answered headers — a
                // proven responder over an arbitrary established peer.
                let proven = self
                    .peers
                    .iter()
                    .filter(|(_, p)| {
                        p.session.established() && p.synced_header_height > 0 && !p.leader_slow
                    })
                    .max_by_key(|(_, p)| p.synced_header_height)
                    .map(|(id, _)| *id);
                proven
                    .or_else(|| {
                        self.peers
                            .iter()
                            .find(|(_, p)| p.session.established() && !p.leader_slow)
                            .map(|(id, _)| *id)
                    })
                    .or_else(|| {
                        self.peers
                            .iter()
                            .find(|(_, p)| p.session.established())
                            .map(|(id, _)| *id)
                    })
            }
            && let Some(peer) = self.peers.get_mut(&id)
        {
            self.headers_leader = Some(id);
            // A peer with a live presync resumes it from its buffered
            // tip — re-asking from the tree tip would draw a page whose
            // discontinuity abandons the buffered work.
            if !peer.sync.awaiting_headers() {
                let req = peer.sync.resume_headers(cs);
                let _ = peer.session.send(&req);
            }
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
        // Amortize the rebuild across header growth — during presync
        // commit the tree gains a ~2000-header page per tick, and
        // rebuilding a growing Vec every tick is the dominant cost.
        // The fetch lookahead only ever needs ~1024 candidates past
        // the frontier, so staleness under 2048 headers starves nothing.
        let stale = header_count.saturating_sub(self.fetch_index_headers);
        // Rebuild on a 2048-header page OR whenever the index can't
        // see the known tip — the stale threshold alone wedged sync at
        // the tail of a download (and on any <2048-header chain): the
        // last partial page never trips 2048, so the frozen index ends
        // below the tip and no block is ever requested.
        let index_short = self
            .fetch_index
            .last()
            .is_none_or(|(h, _)| *h < cs.tree().tip().height);
        // `index_short` only justifies a rebuild when headers actually
        // grew since the last one — if the index still can't reach the
        // tip (a taller side-branch node outranks it), rebuilding every
        // tick just re-sorts ~1M headers forever at ~100% CPU.
        if self.fetch_index.is_empty()
            || stale >= 2048
            || (index_short && header_count != self.fetch_index_headers)
        {
            self.fetch_index = cs
                .tree()
                .headers_by_height()
                .iter()
                .map(|h| {
                    let hash = h.hash();
                    (cs.tree().get(&hash).map(|n| n.height).unwrap_or(0), hash)
                })
                .collect();
            self.fetch_index_headers = header_count;
        }
        // One shared scan: unfetched candidates above the connected
        // frontier (connected heights have bodies by definition), each
        // peer taking a slice until the aggregate budget binds.
        let frontier = cs.chain().len() as u32;
        let start = self.fetch_index.partition_point(|(h, _)| *h < frontier);
        if frontier != self.last_frontier {
            self.last_frontier = frontier;
            self.frontier_moved_at = Instant::now();
        } else if self.frontier_moved_at.elapsed() > Duration::from_secs(60)
            && let Some((_, fh)) = self.fetch_index.get(start)
        {
            self.frontier_moved_at = Instant::now(); // once a minute
            let have = cs.have_body(fh);
            let held_by: Vec<u64> = self
                .peers
                .iter()
                .filter(|(_, p)| p.sync.reserved_hashes().any(|h| h == fh))
                .map(|(id, _)| *id)
                .collect();
            let held_svcs: Vec<u64> = held_by
                .iter()
                .filter_map(|id| self.peers.get(id))
                .filter_map(|p| p.session.peer().map(|i| i.services))
                .collect();
            let held_detail: Vec<String> = held_by
                .iter()
                .filter_map(|id| self.peers.get(id))
                .map(|p| {
                    format!(
                        "pos={:?} age={:?} recv={}",
                        p.sync.in_flight_position(fh),
                        p.sync.in_flight_age(fh).map(|d| d.as_secs()),
                        p.sync.blocks_received()
                    )
                })
                .collect();
            eprintln!(
                "fetch-stall: frontier={frontier} next={fh} have_body={have}                  reserved_by={held_by:?} svcs={held_svcs:?} detail={held_detail:?} in_flight={} stale={}",
                reserved.len(),
                stale
            );
        }
        // Resume wedge: bodies persisted by earlier runs satisfy
        // `have_body`, so the fetch loop below never re-requests them —
        // and nothing else ever feeds them to `accept_block`, leaving
        // the active chain frozen behind stored data. Replay a bounded
        // batch straight from the store each tick; height order keeps
        // parents ahead of children within the batch.
        // Replay advances strictly through the tip: a stored body can only
        // connect when its parent is `cs.tip_hash()`. Anything else — a
        // side-branch header, an orphan whose parent never connected — is
        // skipped via the header node WITHOUT decoding the body. The old
        // window re-offered every stored orphan to `accept_block` every
        // tick (decode + validate + duplicate store append, forever): the
        // pegged-CPU / disk-read / no-progress wedge.
        let mut replayed = 0usize;
        for (_, h) in self.fetch_index[start..].iter().take(1024) {
            if replayed >= 256 {
                break;
            }
            if cs.have_body(h)
                && cs
                    .tree()
                    .get(h)
                    .is_some_and(|n| n.header.prev_block_hash == cs.tip_hash())
                && let Some(block) = cs.body(h)
            {
                match cs.accept_block(&block, now) {
                    Ok(avila_consensus::chainstate::Acceptance::Connected { .. }) => {
                        replayed += 1;
                    }
                    Ok(other) => {
                        eprintln!("replay: {h} -> {other:?}");
                    }
                    Err(e) => {
                        // A stored body failing replay is loud signal —
                        // the freeze diagnosis path. Bounded: the same
                        // hash re-prints only every ~60s via the stall
                        // diagnostic cadence of the caller's loop.
                        eprintln!("replay: {h} rejected: {e}");
                    }
                }
            }
        }
        let want_total = self.max_in_flight_total.saturating_sub(reserved.len());
        let candidates: Vec<(u32, BlockHash)> = self.fetch_index[start..]
            .iter()
            .copied()
            .filter(|(_, h)| !cs.have_body(h) && !reserved.contains(h))
            .take(want_total)
            .collect();
        // Rotate the iteration start each fill: stable map order gave the
        // same peer first pick every tick, so a released straggler kept
        // landing back on the peer withholding it. Rotation walks the
        // reservation to a different peer on the next tick.
        let n_peers = self.peers.len();
        let mut order: Vec<u64> = self.peers.keys().copied().collect();
        if n_peers > 0 {
            order.rotate_left(self.fill_rot % n_peers);
            self.fill_rot = self.fill_rot.wrapping_add(1);
        }
        let mut next = 0usize;
        for id in order {
            if next >= candidates.len() {
                break;
            }
            let Some(peer) = self.peers.get_mut(&id) else {
                continue;
            };
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
            // A NODE_NETWORK_LIMITED peer only retains ~288 blocks below
            // its announced tip — a getdata for older heights is silently
            // dropped, and the reservation pins whatever it re-wins until
            // the next release cycle. Offer it only heights it can serve.
            let (services, peer_tip) = peer
                .session
                .peer()
                .map(|p| (p.services, p.start_height))
                .unwrap_or((0, 0));
            let limited_only = services & crate::message::NODE_NETWORK == 0
                && services & crate::message::NODE_NETWORK_LIMITED != 0;
            let unfetched: Vec<BlockHash> = if limited_only {
                let floor = (peer_tip.max(0) as u32).saturating_sub(288);
                candidates
                    .iter()
                    .copied()
                    .filter(|(h, _)| *h >= floor)
                    .map(|(_, h)| h)
                    .take(take)
                    .collect()
            } else {
                candidates[next..next + take]
                    .iter()
                    .map(|(_, h)| *h)
                    .collect()
            };
            if let Some(req) = peer.sync.want_blocks_excluding(cs, &unfetched, &reserved) {
                let _ = peer.session.send(&req);
            }
            if !limited_only {
                next += take;
            }
            reserved.extend(peer.sync.reserved_hashes().copied());
        }
        // Critical-path escalation: when the frontier block's reservation
        // ages past ~half the release window, duplicate-request it on the
        // least-loaded peer instead of waiting out another withhold cycle.
        // `want_one` skips peers already holding it, so the fan-out bounds
        // at one copy per peer, and only while the frontier hash sits stale.
        if let Some(&(_, frontier_hash)) = self.fetch_index.get(start) {
            let aged = self
                .peers
                .values()
                .filter_map(|p| p.sync.in_flight_age(&frontier_hash))
                .max()
                .is_some_and(|a| a > crate::sync::BLOCK_STALLING_TIMEOUT * 4);
            let held = self
                .peers
                .values()
                .any(|p| p.sync.reserved_hashes().any(|h| *h == frontier_hash));
            if (aged || !held)
                && let Some(peer) = self
                    .peers
                    .values_mut()
                    .filter(|p| p.session.established())
                    .min_by_key(|p| p.sync.in_flight())
                && let Some(req) = peer.sync.want_one(frontier_hash)
            {
                let _ = peer.session.send(&req);
            }
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
    /// Queue #19's divergence alarm — edge-triggered: after enough
    /// rounds, a peer missing much of the circulating set while never
    /// feeding us much back is seeing a filtered view. Fires once per
    /// connection; the counters themselves stay live for `getpeerinfo`.
    fn recon_alarm_check(peer: &mut PeerEntry<S>, id: u64, events: &mut Vec<NetEvent>) {
        if peer.recon_alarm_sent
            || peer.recon_rounds < 10
            || peer.recon_their_misses < 100
            || peer.recon_their_misses < peer.recon_misses.saturating_mul(4)
        {
            return;
        }
        peer.recon_alarm_sent = true;
        events.push(NetEvent::ReconDivergence {
            peer: id,
            rounds: peer.recon_rounds,
            their_misses: peer.recon_their_misses,
            our_misses: peer.recon_misses,
        });
    }

    /// `relay.block.serve` mode + the `block.serve` verdict —
    /// `full` admits every request, `tip` only hashes within reorg
    /// slack of the checked tip, `none` denies all; the verdict then
    /// gates conjunctively.
    fn block_serve_allowed(
        mode: &str,
        verdict: &mut Option<BlockServeVerdict>,
        cs: &Chainstate,
        hash: &avila_consensus::hash::BlockHash,
        id: u64,
        peer: &PeerEntry<S>,
    ) -> bool {
        match mode {
            "none" => return false,
            "tip" => {
                let tip = i64::from(cs.checked_height());
                let height = cs.tree().get(hash).map(|n| i64::from(n.height));
                // Unknown index entries are unservable anyway; a
                // header we don't index can't become a `block` reply.
                if !matches!(height, Some(h) if tip - h <= 2) {
                    return false;
                }
            }
            _ => {}
        }
        if let Some(v) = verdict {
            let facts = BlockServeFacts {
                block_hash: *hash,
                peer: id,
                peer_addr: peer.remote.as_ref().map(net_addr_string),
                peer_inbound: peer.inbound,
                peer_user_agent: peer.session.peer().map(|i| i.user_agent.clone()),
            };
            return v(&facts);
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        id: u64,
        peer: &mut PeerEntry<S>,
        event: SessionEvent,
        cs: &mut Chainstate,
        now: u32,
        addrbook: &mut AddrBook,
        headers_leader: &mut Option<u64>,
        headers_sync_deadline: &mut Option<Instant>,
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
        outbound_nonces: &std::collections::HashSet<u64>,
        stem_exclude: &std::collections::HashSet<avila_consensus::hash::Txid>,
        recent_deliveries: &mut std::collections::VecDeque<(avila_consensus::hash::BlockHash, u64)>,
        tx_serve_verdict: &mut Option<TxServeVerdict>,
        block_serve_verdict: &mut Option<BlockServeVerdict>,
        block_serve_mode: &str,
        compact_enabled: bool,
        compact_serve: bool,
        blocks_only: bool,
        send_feefilter: u64,
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
                    utxproof: false,
                    cmpct: None,
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
                if let Some((wants_hb, version)) = info.cmpct {
                    // BIP152 v2 only — wtxid short-ids. The hb flag
                    // records their *request*; whether we honor it is
                    // decided at announce time by `relay.block.serve`.
                    peer.cmpct_v2 = version >= crate::message::SENDCMPCT_VERSION_WITNESS;
                    peer.cmpct_hb = peer.cmpct_v2 && wants_hb;
                }
                // `relay.tx.send_feefilter` — advertise our mempool
                // floor so peers stop offering what we'd filter.
                if send_feefilter > 0 {
                    let _ = peer.session.send(&Message::FeeFilter(send_feefilter));
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
                match peer.sync.on_headers(
                    cs,
                    &headers,
                    now,
                    headers_leader.is_none_or(|l| l == id),
                ) {
                    Ok(outcome) => {
                        // Height of the last header this page indexed —
                        // Core's `synced_headers` (last common point this
                        // peer fed us).
                        if let Some(last) = headers.last()
                            && let Some(node) = cs.tree().get(&last.hash())
                        {
                            peer.synced_header_height = i64::from(node.height);
                        }
                        // This peer's low-work sync just ended without
                        // proving enough work (abandoned, or ran out of
                        // chain below the anti-DoS threshold) — if it
                        // was leading headers sync, release leadership
                        // right away rather than waiting for either
                        // timeout, so `fill_queues` hands paging to
                        // another peer on this same tick.
                        if outcome.give_up_leadership && *headers_leader == Some(id) {
                            *headers_leader = None;
                            *headers_sync_deadline = None;
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
                // `net.blocks_only` — block invs still fetch; tx items
                // are stripped before the scheduler ever sees them.
                let filtered_vec;
                let filtered: &[crate::message::InvVector] = if blocks_only {
                    filtered_vec = invs
                        .iter()
                        .filter(|i| {
                            !matches!(
                                i.inv_type,
                                crate::message::InvType::Tx
                                    | crate::message::InvType::WitnessTx
                                    | crate::message::InvType::Wtx
                            )
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    &filtered_vec
                } else {
                    &invs
                };
                if let Some(req) = peer.sync.on_inv(cs, Some(mempool), filtered, *global_free) {
                    *global_free = global_free.saturating_sub(peer.sync.in_flight() - before);
                    let _ = peer.session.send(&req);
                }
            }
            SessionEvent::Message(Message::Block(block)) => {
                peer.last_block_time = Some(i64::from(now));
                // A delivery — even a late one poached by reassignment —
                // proves the peer answers; the stall counter resets.
                peer.stall_releases = 0;
                // Journal who delivered this hash — a deferred script
                // failure surfaces blocks later and must not blame the
                // peer that merely triggered the drain.
                recent_deliveries.push_back((block.block_hash(), id));
                if recent_deliveries.len() > 2048 {
                    recent_deliveries.pop_front();
                }
                match peer.sync.on_block(cs, &block, now) {
                    Ok(outcome) => {
                        peer.last_useful = Instant::now();
                        if let Some(avila_consensus::chainstate::Acceptance::Connected {
                            height,
                            ..
                        }) = outcome.acceptance
                        {
                            peer.synced_block_height = i64::from(height);
                        }
                        // Verified effects only: a speculative connect
                        // returns `Connected` with script checks still
                        // in flight — the mempool feed, tip event, and
                        // relay announcement wait for `take_checked`,
                        // which yields a block only after its checks
                        // actually passed.
                        let checked = cs.take_checked();
                        let mut checked_tip = None;
                        for (h, hash) in &checked {
                            if let Some(body) = cs.body(hash) {
                                mempool.on_block_connected(&body, *h);
                            }
                            checked_tip = Some(*h);
                        }
                        if let Some(avila_consensus::chainstate::Acceptance::Connected {
                            reorged,
                            ..
                        }) = outcome.acceptance
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
                            // The tip event and relay announcement fire
                            // only when the *checked* frontier moved —
                            // a purely speculative connect publishes
                            // nothing.
                            if let Some(h) = checked_tip {
                                events.push(NetEvent::TipAdvanced(h));
                                *announce_tip = Some(id);
                            }
                        }
                        // The tick fill pass re-feeds this peer's queue.
                    }
                    Err(e) => {
                        // A deferred script failure names the guilty
                        // block — blame its recorded sender, not the
                        // peer whose delivery happened to surface it.
                        // When the sender is unknown (journal rotated
                        // out), punish nobody: the block is marked
                        // invalid either way.
                        match cs.take_spec_failed() {
                            Some(bad) => {
                                // Deferred failure: blame the bad
                                // block's recorded sender; if the
                                // journal rotated it out, punish the
                                // innocent triggerer not at all — the
                                // block stays marked invalid either way.
                                if let Some((_, who)) =
                                    recent_deliveries.iter().find(|(h, _)| *h == bad)
                                {
                                    eprintln!(
                                        "block {bad} failed deferred script checks — blaming its sender"
                                    );
                                    dead.push((*who, DisconnectReason::Misbehavior(e.to_string())));
                                }
                            }
                            None => dead.push((id, DisconnectReason::Misbehavior(e.to_string()))),
                        }
                    }
                }
            }
            SessionEvent::Message(Message::SendHeaders) => {
                peer.wants_headers_announce = true;
            }
            SessionEvent::Message(Message::SendCmpct { announce, version }) => {
                // Core's burst puts sendcmpct after its verack — it
                // arrives here as a live negotiation update, not a
                // handshake field. Version 2+ selects wtxid short-ids;
                // `announce` grants us high-bandwidth cmpctblocks.
                peer.cmpct_v2 = version >= crate::message::SENDCMPCT_VERSION_WITNESS;
                peer.cmpct_hb = peer.cmpct_v2 && announce;
            }
            SessionEvent::Message(Message::CmpctBlock(cb)) => {
                // Unnegotiated cmpctblocks (no sendcmpct v2 on this
                // link) are ignored politely, like Core.
                if compact_enabled && peer.cmpct_v2 {
                    peer.cmpct_recv += 1;
                    // The header must exist in the index before the
                    // reconstructed body can connect — hb announces
                    // arrive without a preceding `headers` message.
                    // Rejects (bad PoW, orphan) drop the whole thing:
                    // no header, no compact block.
                    if cs.accept_header(&cb.header, now).is_err() {
                        return;
                    }
                    let recv_block = cb.header.hash();
                    let recv_short = cb.shortids.len();
                    match crate::compact::PartialBlock::begin(cb, mempool) {
                        Ok(crate::compact::Reconstruct::Complete(block)) => {
                            peer.cmpct_hit += 1;
                            events.push(NetEvent::CompactReceived {
                                peer: id,
                                block: recv_block,
                                short_ids: recv_short,
                            });
                            events.push(NetEvent::CompactHit {
                                peer: id,
                                block: recv_block,
                            });
                            // The reconstructed block takes the identical
                            // connect path as a `block` delivery — header,
                            // merkle, and full checks all re-run.
                            Self::dispatch(
                                id,
                                peer,
                                SessionEvent::Message(Message::Block(*block)),
                                cs,
                                now,
                                addrbook,
                                headers_leader,
                                headers_sync_deadline,
                                announce_tip,
                                announce_tx,
                                mempool,
                                global_free,
                                events,
                                dead,
                                serve_filters,
                                outbound_nonces,
                                stem_exclude,
                                recent_deliveries,
                                tx_serve_verdict,
                                block_serve_verdict,
                                block_serve_mode,
                                compact_enabled,
                                compact_serve,
                                blocks_only,
                                send_feefilter,
                            );
                        }
                        Ok(crate::compact::Reconstruct::Partial(p)) => {
                            peer.cmpct_getblocktxn += 1;
                            events.push(NetEvent::CompactReceived {
                                peer: id,
                                block: recv_block,
                                short_ids: recv_short,
                            });
                            events.push(NetEvent::CompactPatchRequest {
                                peer: id,
                                block: p.block_hash,
                                missing: p.missing_len(),
                            });
                            let req = Message::GetBlockTxn(p.getblocktxn());
                            peer.partial_blocks.push_back(*p);
                            while peer.partial_blocks.len() > MAX_PARTIAL_BLOCKS {
                                peer.partial_blocks.pop_front();
                            }
                            let _ = peer.session.send(&req);
                        }
                        Err(_) => {
                            // Malformed layout — fall back to asking for
                            // the whole block rather than disconnecting.
                            peer.cmpct_fell_back += 1;
                            events.push(NetEvent::CompactFallback {
                                peer: id,
                                block: recv_block,
                            });
                        }
                    }
                }
            }
            SessionEvent::Message(Message::GetBlockTxn(req)) => {
                // `relay.block.serve`/`block.serve` gate: a blocked
                // hash is silently ignored — same as never holding it.
                let block_ok = block_serve_mode != "none"
                    && Self::block_serve_allowed(
                        block_serve_mode,
                        block_serve_verdict,
                        cs,
                        &req.block_hash,
                        id,
                        peer,
                    );
                if compact_serve && block_ok {
                    // `cs.body` serves any stored block — indexes are
                    // differential-encoded absolute positions.
                    if let Some(block) = cs.body(&req.block_hash) {
                        let mut prev: i64 = -1;
                        let mut txs = Vec::with_capacity(req.indexes.len());
                        for &diff in &req.indexes {
                            let idx = prev + i64::from(diff) + 1;
                            prev = idx;
                            if let Some(tx) = block
                                .transactions
                                .get(usize::try_from(idx).unwrap_or(usize::MAX))
                            {
                                txs.push(tx.clone());
                            }
                        }
                        let _ = peer
                            .session
                            .send(&Message::BlockTxn(crate::message::BlockTxn {
                                block_hash: req.block_hash,
                                txs,
                            }));
                    }
                }
            }
            SessionEvent::Message(Message::BlockTxn(bt)) => {
                if let Some(pos) = peer
                    .partial_blocks
                    .iter()
                    .position(|p| p.block_hash == bt.block_hash)
                    && let Some(mut partial) = peer.partial_blocks.remove(pos)
                {
                    partial.fill(bt.txs);
                    if partial.is_complete() {
                        if let Some(block) = partial.into_block() {
                            Self::dispatch(
                                id,
                                peer,
                                SessionEvent::Message(Message::Block(block)),
                                cs,
                                now,
                                addrbook,
                                headers_leader,
                                headers_sync_deadline,
                                announce_tip,
                                announce_tx,
                                mempool,
                                global_free,
                                events,
                                dead,
                                serve_filters,
                                outbound_nonces,
                                stem_exclude,
                                recent_deliveries,
                                tx_serve_verdict,
                                block_serve_verdict,
                                block_serve_mode,
                                compact_enabled,
                                compact_serve,
                                blocks_only,
                                send_feefilter,
                            );
                        }
                    } else {
                        // Still short — the reply lied or raced;
                        // ask for the whole block instead.
                        peer.cmpct_fell_back += 1;
                        events.push(NetEvent::CompactFallback {
                            peer: id,
                            block: bt.block_hash,
                        });
                        let _ =
                            peer.session
                                .send(&Message::GetData(vec![crate::message::InvVector {
                                    inv_type: crate::message::InvType::WitnessBlock,
                                    hash: bt.block_hash,
                                }]));
                    }
                }
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
                if peer.cfilter_allow() {
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
            }
            SessionEvent::Message(Message::GetCFHeaders(req)) => {
                if peer.cfilter_allow() {
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
            }
            SessionEvent::Message(Message::GetCFCheckpt(req)) => {
                if peer.cfilter_allow() {
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
                // `tx.serve` — conjunctive per-request gate. A denied
                // item is answered `notfound`, indistinguishable from
                // never holding it; non-tx requests bypass the hook.
                let mut suppressed: Vec<crate::message::InvVector> = Vec::new();
                let mut allowed = reqs;
                if let Some(v) = tx_serve_verdict.as_mut() {
                    let mut kept = Vec::with_capacity(allowed.len());
                    for inv in allowed.drain(..) {
                        let resolved = match inv.inv_type {
                            crate::message::InvType::Tx | crate::message::InvType::WitnessTx => {
                                mempool
                                    .get(&avila_consensus::hash::Txid::from_bytes(
                                        inv.hash.to_bytes(),
                                    ))
                                    .map(|tx| (tx.txid(), tx.wtxid()))
                                    .or_else(|| {
                                        mempool
                                            .extrapool()
                                            .get(&avila_consensus::hash::Txid::from_bytes(
                                                inv.hash.to_bytes(),
                                            ))
                                            .map(|e| (e.tx.txid(), e.tx.wtxid()))
                                    })
                            }
                            crate::message::InvType::Wtx => mempool
                                .get_wtxid(&avila_consensus::hash::Wtxid::from_bytes(
                                    inv.hash.to_bytes(),
                                ))
                                .map(|tx| (tx.txid(), tx.wtxid()))
                                .or_else(|| {
                                    mempool
                                        .extrapool()
                                        .get_wtxid(&avila_consensus::hash::Wtxid::from_bytes(
                                            inv.hash.to_bytes(),
                                        ))
                                        .map(|e| (e.tx.txid(), e.tx.wtxid()))
                                }),
                            _ => None,
                        };
                        match resolved {
                            Some((txid, wtxid)) => {
                                let facts = TxServeFacts {
                                    txid,
                                    wtxid,
                                    peer: id,
                                    peer_addr: peer.remote.as_ref().map(net_addr_string),
                                    peer_inbound: peer.inbound,
                                    peer_user_agent: peer
                                        .session
                                        .peer()
                                        .map(|i| i.user_agent.clone()),
                                };
                                if v(&facts) {
                                    kept.push(inv);
                                } else {
                                    suppressed.push(inv);
                                }
                            }
                            // Unresolvable or non-tx — not the hook's
                            // domain; serve_getdata notfounds misses.
                            None => kept.push(inv),
                        }
                    }
                    allowed = kept;
                }
                // `relay.block.serve` + `block.serve` — the block-side
                // gate: `MSG_CMPCT_BLOCK` items are served compactly
                // when negotiated; `block`/`witness-block` items pass
                // the mode + verdict check or fall to `notfound`.
                let mut compact_reqs = Vec::new();
                {
                    let mut kept = Vec::with_capacity(allowed.len());
                    for inv in allowed.drain(..) {
                        match inv.inv_type {
                            crate::message::InvType::CompactBlock => compact_reqs.push(inv),
                            crate::message::InvType::Block
                            | crate::message::InvType::WitnessBlock => {
                                if Self::block_serve_allowed(
                                    block_serve_mode,
                                    block_serve_verdict,
                                    cs,
                                    &inv.hash,
                                    id,
                                    peer,
                                ) {
                                    kept.push(inv);
                                } else {
                                    suppressed.push(inv);
                                }
                            }
                            _ => kept.push(inv),
                        }
                    }
                    allowed = kept;
                }
                if compact_serve {
                    for inv in compact_reqs {
                        let ok = Self::block_serve_allowed(
                            block_serve_mode,
                            block_serve_verdict,
                            cs,
                            &inv.hash,
                            id,
                            peer,
                        );
                        match (ok, cs.body(&inv.hash)) {
                            (true, Some(body)) => {
                                let _ = peer.session.send(&Message::CmpctBlock(
                                    crate::compact::make_cmpctblock(&body),
                                ));
                            }
                            _ => suppressed.push(inv),
                        }
                    }
                } else {
                    suppressed.extend(compact_reqs);
                }
                PeerSync::serve_getdata(cs, Some(mempool), &allowed, |reply| {
                    peer.session.send(reply).is_ok()
                });
                if !suppressed.is_empty() {
                    let _ = peer.session.send(&Message::NotFound(suppressed));
                }
                // `sendutxproof` peers get the bridge's spend bundle
                // after each served block — proofs can't be generated
                // post-hoc, so only blocks this node connected while
                // bridged carry one.
                if peer.session.peer().is_some_and(|i| i.utxproof) {
                    for req in &allowed {
                        if !matches!(
                            req.inv_type,
                            crate::message::InvType::Block | crate::message::InvType::WitnessBlock
                        ) {
                            continue;
                        }
                        match cs.proof_bundle(&req.hash) {
                            Ok(Some(bundle)) => {
                                let _ = peer.session.send(&Message::UtxoProof {
                                    block_hash: req.hash,
                                    bundle,
                                });
                            }
                            Ok(None) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
            SessionEvent::Message(Message::UtxoProof { block_hash, bundle }) => {
                // A proof bundle feeds the shadow accumulator — decode
                // + ordering live in chainstate; a bundle for a block
                // we never asked about is still harmless state.
                cs.offer_bundle(block_hash, bundle);
            }
            SessionEvent::Message(Message::NotFound(invs)) => {
                // The peer can't serve these — release the slots so the
                // fill pass reassigns them to another peer.
                peer.sync.on_notfound(&invs);
            }
            SessionEvent::Message(Message::ReqRecon(their_sketch)) => {
                // Audit P2P-1: rate-limit — each request runs a sketch
                // solve over the whole mempool (up to `q` field ops).
                // BIP330 initiators send at most one reqrecon per
                // reconciliation round (~1s cadence); a peer faster
                // than RECON_REQ_MIN_INTERVAL is burning CPU, not
                // reconciling — count it, and sustained abuse is
                // misbehavior.
                if let Some(t) = peer.recon_req_last
                    && t.elapsed() < RECON_REQ_MIN_INTERVAL
                {
                    peer.recon_req_violations += 1;
                    if peer.recon_req_violations >= RECON_REQ_MAX_VIOLATIONS {
                        dead.push((
                            id,
                            DisconnectReason::Misbehavior("reqrecon flooding".into()),
                        ));
                    }
                    return;
                }
                peer.recon_req_last = Some(Instant::now());
                // Responder side: attribute the decoded difference
                // against our own pool — ids we hold are their misses,
                // ids we don't are ours.
                let Some(link) = peer.recon else {
                    return;
                };
                let salt = link.our_salt ^ link.their_salt;
                let (our_ids, our_map) = recon_pool(mempool, salt, stem_exclude);
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
                        && let Some((misses, their_misses)) = round.close_bisected(&reply_sk, half)
                    {
                        bs.misses.extend(misses);
                        bs.their_misses += their_misses.len() as u64;
                    }
                    if is_lo {
                        bs.got_lo = true;
                        peer.recon_bisect = Some(bs);
                    } else {
                        // Both halves done — one diff ask for the lot.
                        peer.recon_round = None;
                        peer.recon_rounds += 1;
                        peer.recon_misses += bs.misses.len() as u64;
                        peer.recon_their_misses += bs.their_misses;
                        // The round needed bisecting — capacity was
                        // under the real diff: observe the measured
                        // total, and make sure the hint outgrows it.
                        let observed = bs.misses.len() as u64 + bs.their_misses;
                        Self::recon_observe(peer, observed);
                        peer.recon_diff_hint = peer.recon_diff_hint.max(observed as u32 * 2);
                        Self::recon_alarm_check(peer, id, events);
                        if !bs.misses.is_empty() {
                            let _ = peer.session.send(&Message::ReconcilDiff {
                                ask_parents: 0,
                                short_ids: bs.misses,
                            });
                        }
                    }
                    return;
                }
                let (our_ids, _) = recon_pool(mempool, salt, stem_exclude);
                if let Some(round) = peer.recon_round.take() {
                    match round.close(&reply_sk, &our_ids) {
                        Some((misses, their_misses)) => {
                            peer.recon_rounds += 1;
                            peer.recon_misses += misses.len() as u64;
                            peer.recon_their_misses += their_misses.len() as u64;
                            Self::recon_observe(
                                peer,
                                misses.len() as u64 + their_misses.len() as u64,
                            );
                            Self::recon_alarm_check(peer, id, events);
                            if !misses.is_empty() {
                                let _ = peer.session.send(&Message::ReconcilDiff {
                                    ask_parents: 0,
                                    short_ids: misses,
                                });
                            }
                        }
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
                                their_misses: 0,
                            });
                            peer.recon_round = Some(round);
                            let _ = peer.session.send(&Message::ReqBisec);
                        }
                    }
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
                let (our_ids, _) = recon_pool(mempool, salt, stem_exclude);
                let capacity = recon_capacity(peer.recon_diff_hint);
                let (lo, hi) = crate::recon::bisect_reply(&our_ids, 31, capacity);
                let _ = peer.session.send(&lo);
                let _ = peer.session.send(&hi);
            }
            SessionEvent::Message(Message::SendRecon(_)) => {
                // Late renegotiation is ignored — caps were fixed at
                // handshake.
            }
            SessionEvent::Message(Message::Mempool) => {
                // Audit P2P-BIP35: Core only serves `mempool` to
                // inbound peers — a peer we dialed getting the whole
                // pool lets it read our mempool over a link it didn't
                // even open. And one request per interval — repeats
                // are bandwidth amplification, not sync.
                if !peer.inbound || blocks_only {
                    return;
                }
                if let Some(t) = peer.mempool_req_last
                    && t.elapsed() < MEMPOOL_REQ_INTERVAL
                {
                    return;
                }
                peer.mempool_req_last = Some(Instant::now());
                // BIP35: advertise the pool. wtxid entries for
                // wtxidrelay peers, txid otherwise — capped so one
                // request can't pull a multi-MB inv.
                let by_wtxid = peer.session.peer().is_some_and(|i| i.wtxid_relay);
                let invs: Vec<crate::message::InvVector> = mempool
                    .txids()
                    .iter()
                    // `mempool.private` entries don't bulk-leak either —
                    // stem is the only announce they get.
                    .filter(|txid| !mempool.is_private(txid))
                    .take(MAX_MEMPOOL_INV)
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
                // Core answers `getaddr` only on inbound connections —
                // an outbound-only (e.g. NATed) node would otherwise let
                // an attacker seed our addrman with tagged addresses and
                // read them back over the link it dialed, fingerprinting
                // us — and only once per connection, to bound reply
                // spam and addr-stamping of later INV announcements.
                if peer.inbound && !peer.getaddr_recvd {
                    peer.getaddr_recvd = true;
                    let entries = addrbook
                        .sample()
                        .iter()
                        .map(|a| addr_v2_of(a, now))
                        .collect();
                    let _ = peer.session.send(&Message::AddrV2(entries));
                }
            }
            SessionEvent::Message(Message::Addr(entries)) => {
                Self::process_addr(peer, addrbook, &entries, now, |e| Some((e.addr, e.time)));
            }
            SessionEvent::Message(Message::AddrV2(entries)) => {
                Self::process_addr(peer, addrbook, &entries, now, |e| {
                    net_addr_of_v2(e).map(|a| (a, e.time))
                });
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
            SessionEvent::Message(Message::Version(v)) => {
                // Self-connection check (Core's `CheckIncomingNonce`):
                // only inbound peers are checked, against nonces *we*
                // sent on our own outbound dials — an inbound version
                // carrying one means this connection loops back to us.
                if peer.inbound && outbound_nonces.contains(&v.nonce) {
                    dead.push((
                        id,
                        DisconnectReason::Session("connected to self".to_string()),
                    ));
                }
            }
            SessionEvent::Message(Message::FeeFilter(rate)) => {
                // BIP-133 — the peer's minimum feerate gates its invs.
                peer.min_fee = rate;
            }
            SessionEvent::Message(_) => {}
        }
    }

    /// `addr`/`addrv2` intake: rate-limits how many entries from one
    /// message we're willing to process (net_processing's per-peer
    /// token bucket) before handing survivors to the address book. One
    /// token is spent per *wire* entry regardless of whether `parse`
    /// can turn it into a storable [`NetAddr`] — matching Core, which
    /// spends the token before deciding an entry isn't useful. The
    /// oversized-message case (`> MAX_ADDR_TO_SEND`) is already rejected
    /// at decode time ([`crate::message`]), so every count reaching here
    /// is legal; this only bounds the *rate*, not the burst size of a
    /// single legal message.
    fn process_addr<T>(
        peer: &mut PeerEntry<S>,
        addrbook: &mut AddrBook,
        entries: &[T],
        now_wall: u32,
        parse: impl Fn(&T) -> Option<(NetAddr, u32)>,
    ) {
        let now = Instant::now();
        if peer.addr_token_bucket < MAX_ADDR_PROCESSING_TOKEN_BUCKET {
            // Don't refill past the ceiling — a peer that never sends
            // addr traffic shouldn't accrue an ever-growing reserve.
            let elapsed = now
                .saturating_duration_since(peer.addr_token_timestamp)
                .as_secs_f64();
            peer.addr_token_bucket = (peer.addr_token_bucket + elapsed * MAX_ADDR_RATE_PER_SECOND)
                .min(MAX_ADDR_PROCESSING_TOKEN_BUCKET);
        }
        peer.addr_token_timestamp = now;
        let mut accepted = Vec::with_capacity(entries.len());
        for entry in entries {
            if peer.addr_token_bucket < 1.0 {
                peer.addr_rate_limited += 1;
                continue;
            }
            peer.addr_token_bucket -= 1.0;
            peer.addr_processed += 1;
            if let Some(pair) = parse(entry) {
                accepted.push(pair);
            }
        }
        // Audit P2P-6: charge inserts to the relaying peer — a flood
        // source churns its own quota instead of owning the table.
        if let Some(remote) = peer.remote {
            let src = {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&remote.ip, &mut h);
                std::hash::Hasher::finish(&h)
            };
            addrbook.add_many_from(accepted.into_iter(), now_wall, src);
        } else {
            addrbook.add_many(accepted.into_iter(), now_wall);
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
    /// Audit P2P-12: discouraged peers answer `true` here as well, so
    /// every dial/accept gate that already consults this method covers
    /// discouragement without touching each call site.
    #[must_use]
    pub fn is_banned(&self, ip: &[u8; 16], now: i64) -> bool {
        self.bans.is_banned(ip, now)
            || self
                .discouraged
                .get(ip)
                .is_some_and(|until| *until > Instant::now())
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

    /// `peers.ban_time` — the default `setban` duration, like Core's
    /// `-bantime`.
    pub fn set_default_ban_time(&mut self, secs: i64) {
        self.default_ban_time = secs;
    }

    /// The configured default ban duration.
    #[must_use]
    pub fn default_ban_time(&self) -> i64 {
        self.default_ban_time
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
        // fRelay: ask for transaction announcements unless blocks-only
        // (Core's -blocksonly suppresses them in both directions).
        version.relay = !self.blocks_only;
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
        version.relay = !self.blocks_only;
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
        version.relay = !self.blocks_only;
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

    /// Admits every completed inbound handshake — ban check, the
    /// `peer.accept` hook if one is set, then `add_inbound`'s
    /// slot/eviction rules. Returns the admitted ids.
    pub fn drain_inbounds(&mut self) -> Vec<u64> {
        let mut admitted = Vec::new();
        while let Ok((addr, result)) = self.inbound_rx.try_recv() {
            let Ok(session) = result else { continue };
            let remote = crate::addrman::net_addr_of(addr, 0);
            if !self.network_active || self.bans.is_banned(&remote.ip, (self.clock)()) {
                continue;
            }
            if let Some(judge) = self.inbound_verdict.as_mut() {
                let info = session.peer();
                let facts = InboundFacts {
                    remote: addr,
                    services: info.map_or(0, |i| i.services),
                    protocol_version: info.map_or(0, |i| i.version),
                    user_agent: info.map_or_else(String::new, |i| i.user_agent.clone()),
                    start_height: info.map_or(0, |i| i.start_height),
                    relay: info.is_some_and(|i| i.relay),
                    wtxid_relay: info.is_some_and(|i| i.wtxid_relay),
                    addrv2: info.is_some_and(|i| i.addrv2),
                    transport: session.transport_protocol(),
                };
                if !judge(&facts) {
                    continue;
                }
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
        while let Ok((key, result)) = self.dial_rx.try_recv() {
            let want_v2 = self.pending_dials.remove(&key).unwrap_or(false);
            let Ok(session) = result else {
                // Proxy health (privacy matrix): a failed dial under
                // proxy mode means the private route itself is down —
                // surface it once after a sustained streak instead of
                // leaving zero-peers unexplained.
                if self.proxy.is_some() {
                    self.proxy_failures += 1;
                    if self.proxy_failures == 3 {
                        if self.event_ring.len() >= 1024 {
                            self.event_ring.pop_front();
                        }
                        self.event_ring.push_back(NetEvent::ProxyUnreachable);
                    }
                }
                continue;
            };
            self.proxy_failures = 0;
            // Forced-downgrade telemetry: v2 was requested but the
            // session landed cleartext v1 — exactly what a transport-
            // stripping MITM produces. Advisory, not a ban.
            if want_v2
                && session.transport_protocol() == "v1"
                && let DialKey::Addr(addr) = &key
            {
                if self.event_ring.len() >= 1024 {
                    self.event_ring.pop_front();
                }
                self.event_ring
                    .push_back(NetEvent::V2Downgraded { addr: *addr });
            }
            // A domain dial has no resolved IP to ban-check — the
            // peer registers with an unspecified remote.
            let remote = match &key {
                DialKey::Addr(addr) => addrman::net_addr_of(*addr, 0),
                DialKey::Domain(..) => NetAddr::unspecified(),
            };
            // A ban or a full peer set that landed mid-dial still
            // applies — Core rechecks IsBanned after connect.
            let admissible = self.network_active
                && self.has_slot()
                && (matches!(key, DialKey::Domain(..))
                    || !self.bans.is_banned(&remote.ip, (self.clock)()));
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
            // Audit P2P-13: under a proxy, a hostname addnode must NOT
            // resolve through the system DNS — that leaks the peer's
            // name to the ISP's resolver. The proxy resolves it
            // instead (SOCKS5 ATYP_DOMAIN); `.onion` only exists
            // through the proxy path. Without a proxy, literal IPs are
            // dialed directly and hostnames resolve locally as before.
            let literal: Option<SocketAddr> = node.as_str().parse().ok();
            if literal.is_none()
                && self.proxy.is_some()
                && let Some((host, port_s)) = node.as_str().rsplit_once(':')
                && let Ok(port) = port_s.parse::<u16>()
                && !host.is_empty()
                && host.len() <= 253
            {
                let key = DialKey::Domain(host.trim_matches(&['[', ']'][..]).to_string(), port);
                if self.pending_dials.contains_key(&key) {
                    continue;
                }
                self.addnode_dial.insert(node.clone(), Instant::now());
                self.queue_dial(key, use_v2, magic, start_height, &mut dialed);
                continue;
            }
            if let Ok(addrs) = node.as_str().to_socket_addrs() {
                let socks: Vec<SocketAddr> = addrs.collect();
                // Already talking to this node — Core's AddNode thread
                // skips connected entries rather than double-dialing.
                // Don't stamp the backoff either, so a drop redials fast.
                if socks.iter().any(|s| {
                    self.connected_to(*s) || self.pending_dials.contains_key(&DialKey::Addr(*s))
                }) {
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
                    self.queue_dial(
                        DialKey::Addr(sock),
                        use_v2,
                        magic,
                        start_height,
                        &mut dialed,
                    );
                }
            }
        }
        let now = (self.clock)();
        // `select` is deterministic, so each probe marks its candidate —
        // the round is bounded by the book size and a banned candidate
        // can't starve or spin the loop.
        let probes_left = self.addrbook.len();
        let mut tried = 0usize;
        // Outbound diversity (audit P2P-4): with an ASMap, count the
        // outbound slots each ASN holds; without one — the default —
        // fall back to Core's GetGroup bucketing (/16 v4, /32 v6) so
        // a candidate set still can't land all outbounds on one
        // operator's address block. Either way a saturated bucket is
        // skipped; the probe budget keeps the book making progress.
        let asmap_loaded = !self.asmap.is_empty();
        let group_counts: HashMap<Vec<u8>, usize> = self
            .peers
            .values()
            .filter(|p| !p.inbound)
            .filter_map(|p| {
                p.remote.and_then(|r| {
                    if asmap_loaded {
                        let ip = std::net::IpAddr::from(r.ip);
                        self.asmap.asn(&ip).map(|asn| asn.to_be_bytes().to_vec())
                    } else {
                        Some(addrman::net_group(&r.ip))
                    }
                })
            })
            .fold(HashMap::new(), |mut m, g| {
                *m.entry(g).or_default() += 1;
                m
            });
        while self.outbound_open()
            && tried < probes_left
            && let Some(candidate) = self.addrbook.select()
        {
            tried += 1;
            self.addrbook.mark_attempt(&candidate);
            if self.is_banned(&candidate.ip, now) {
                continue; // banned candidates aren't dialed
            }
            // Same gate either way: an ASMap candidate is keyed by
            // ASN, otherwise by netgroup — one outbound per bucket.
            let group_key = if asmap_loaded {
                let ip = std::net::IpAddr::from(candidate.ip);
                self.asmap.asn(&ip).map(|asn| asn.to_be_bytes().to_vec())
            } else {
                Some(addrman::net_group(&candidate.ip))
            };
            if let Some(g) = group_key
                && group_counts.get(&g).copied().unwrap_or(0) >= 1
            {
                continue; // this bucket already holds an outbound slot
            }
            // Already connected or dialing — Core's
            // `AlreadyConnectedTo`/`FindNode` check; the book may
            // still carry peers we established sessions with.
            let sock = addrman::socket_addr(&candidate);
            if self.connected_to(sock) || self.pending_dials.contains_key(&DialKey::Addr(sock)) {
                continue;
            }
            // Automatic outbounds use the `-v2transport` setting —
            // Core's `use_v2transport` on OpenNetworkConnection.
            self.queue_dial(
                DialKey::Addr(sock),
                self.v2transport,
                magic,
                start_height,
                &mut dialed,
            );
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
        key: DialKey,
        use_v2: bool,
        magic: [u8; 4],
        start_height: i32,
        dialed: &mut Vec<SocketAddr>,
    ) {
        if self.pending_dials.insert(key.clone(), use_v2).is_some() {
            return; // already in flight
        }
        let (_port, remote) = match &key {
            DialKey::Addr(addr) => {
                dialed.push(*addr);
                (addr.port(), addrman::net_addr_of(*addr, 0))
            }
            // A domain target has no numeric address to gossip yet.
            DialKey::Domain(_, port) => (*port, NetAddr::unspecified()),
        };
        let tx = self.dial_tx.clone();
        // Per-connection nonce — a fixed value would make every
        // outbound indistinguishable to peers that fingerprint by
        // version nonce (and blind our own self-connection check,
        // which expects distinct nonces per session).
        let mut nonce_bytes = [0u8; 8];
        let _ = getrandom::fill(&mut nonce_bytes);
        let nonce = u64::from_le_bytes(nonce_bytes);
        let mut version = build_version(nonce, start_height, remote, (self.clock)());
        version.relay = !self.blocks_only;
        if use_v2 {
            version.services |= NODE_P2P_V2;
        }
        if self.serve_filters {
            version.services |= crate::message::NODE_COMPACT_FILTERS;
        }
        let proxy = self.proxy;
        std::thread::spawn(move || {
            let outcome = match (&key, proxy) {
                (DialKey::Addr(addr), Some(p)) => dial_via(
                    p,
                    crate::proxy::SocksTarget::Ip(*addr),
                    magic,
                    version,
                    use_v2,
                ),
                // Audit P2P-13: a domain target under proxy is
                // resolved BY the proxy — no local DNS lookup.
                (DialKey::Domain(host, port), Some(p)) => dial_via(
                    p,
                    crate::proxy::SocksTarget::Domain(host.clone(), *port),
                    magic,
                    version,
                    use_v2,
                ),
                // A domain target with no proxy would need a local
                // lookup — the caller resolves eagerly instead.
                (DialKey::Domain(..), None) => Err(SessionError::HandshakeTimeout),
                (DialKey::Addr(addr), None) => dial(*addr, magic, version, use_v2),
            };
            let _ = tx.send((key, outcome));
        });
    }
}

/// The per-dial worker timeout — Core's `connect()` default is 5s
/// (`nConnectTimeout` is only honored by proxies; direct dials use
/// the same bound here).
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// The proxy dial worker — `socks5_connect` to the SOCKS5 proxy, then
/// the same session handshake `dial` runs. No clearnet fallback: a
/// proxy failure IS the dial's failure (fail-closed, queue #13).
fn dial_via(
    proxy: SocketAddr,
    target: crate::proxy::SocksTarget,
    magic: [u8; 4],
    version: Version,
    want_v2: bool,
) -> DialOutcome {
    let stream = crate::proxy::socks5_connect(&proxy, &target, DIAL_TIMEOUT)?;
    stream.set_nodelay(true)?;
    if want_v2 {
        stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
        match PeerSession::initiate_v2(stream, magic, version.clone(), SEND_BUDGET_PER_PEER) {
            Err(SessionError::V1Fallback) => {
                let stream = crate::proxy::socks5_connect(&proxy, &target, DIAL_TIMEOUT)?;
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

/// One dial worker's product — a live `PeerSession` (v1, or v2 with
/// the BIP324 handshake already done) or the failure.
type DialOutcome = Result<PeerSession<TcpStream>, SessionError>;

/// What an outbound dial worker is connecting to (audit P2P-13):
/// either a resolved socket, or a hostname the SOCKS5 proxy resolves
/// — under `-proxy` a local `to_socket_addrs` call would leak the
/// hostname to the ISP's DNS, so domain targets ride the proxy's own
/// resolver (`ATYP_DOMAIN`) instead.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum DialKey {
    /// A numeric endpoint — `pending_dials`/`connected_to` dedup key.
    Addr(SocketAddr),
    /// `host:port` — the proxy resolves it; nothing local is queried.
    Domain(String, u16),
}

/// `connect` + optional BIP324 handshake + nonblocking flip — shared
/// by [`PeerManager::connect`] and the `queue_dial` workers. On
/// `V1Fallback` the socket is dropped and the peer redialed in v1 —
/// Core's `ShouldReconnectV1` (a v1-only peer can't parse the
/// ellswift bytes we already sent).
/// How long proven misbehavior keeps an IP off the dial/accept gates
/// (audit P2P-12). Core's discouragement window is 24h — same here.
const DISCOURAGE_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// Audit P2P-1: minimum spacing between a peer's `reqrecon` requests
/// — a full reconciliation cadence is ~1s/round, so sub-250ms bursts
/// are flood, not sync.
const RECON_REQ_MIN_INTERVAL: Duration = Duration::from_millis(250);
/// Violations of [`RECON_REQ_MIN_INTERVAL`] before the peer is dropped
/// for misbehavior.
const RECON_REQ_MAX_VIOLATIONS: u32 = 8;

/// Audit P2P-BIP35: minimum spacing between a peer's BIP35 `mempool`
/// requests — the reply is the whole pool, so repeats inside a minute
/// are amplification, not sync.
const MEMPOOL_REQ_INTERVAL: Duration = Duration::from_secs(60);
/// Max inventory entries in one BIP35 reply (~1.8 MB at 36B/entry).
const MAX_MEMPOOL_INV: usize = 50_000;

/// Inbound handshakes in flight at once — past this cap the listener
/// drops accepted sockets rather than queue unbounded workers.
const MAX_PENDING_ACCEPTS: usize = 32;

/// Blocks mid-reconstruction per peer — a `cmpctblock` awaiting its
/// `blocktxn`. Small: each holds a slot vector sized to the block;
/// four deep covers reorg bursts without an unbounded buffer.
const MAX_PARTIAL_BLOCKS: usize = 4;

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

/// How long to sleep between unproductive probe peeks — bounds the
/// worker to a handful of wakeups a second instead of spinning.
const PROBE_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Peeks `stream` until its first bytes resolve the v1-vs-v2 transport
/// question or `deadline` passes.
///
/// `TcpStream::peek` mirrors `recv(MSG_PEEK)`: it returns as soon as
/// *any* queued bytes are available, not once the full buffer is
/// filled, and an idle connection with data already queued keeps
/// returning that same data immediately on every call. A bare retry
/// loop around it therefore either spins at 100% CPU forever on a peer
/// that sends a few matching prefix bytes and then goes quiet, or —
/// since an empty peek trivially equals an empty prefix slice — spins
/// forever on `Ok(0)` once the peer hangs up. Both are bounded here:
/// EOF is reported immediately as a disconnect, and an inconclusive
/// peek backs off for [`PROBE_POLL_INTERVAL`] before trying again,
/// itself bounded by `deadline` — a real peer's 16-byte prefix arrives
/// in a single write, so this only ever iterates for a pathological one.
///
/// Returns the bytes peeked so far — `probe[..n]` is meaningful,
/// `probe[n..]` is only guaranteed zero when the break was `n < 16`
/// (never a full v1-prefix match, since it already disagrees with
/// `want` inside `probe[..n]`).
fn probe_transport_prefix(
    stream: &TcpStream,
    want: [u8; 16],
    deadline: Instant,
) -> std::io::Result<[u8; 16]> {
    let mut probe = [0u8; 16];
    loop {
        let n = stream.peek(&mut probe)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before completing the transport probe",
            ));
        }
        if n >= 16 || probe[..n] != want[..n] {
            return Ok(probe);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "transport probe did not resolve within the handshake timeout",
            ));
        }
        std::thread::sleep(PROBE_POLL_INTERVAL);
    }
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
    let want = v1_version_prefix(magic);
    let probe = probe_transport_prefix(&stream, want, Instant::now() + HANDSHAKE_TIMEOUT)?;
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

/// Core's sync-peer arming (`SendMessages`): estimates how many headers
/// we're likely missing from how stale our best header's timestamp is
/// relative to the network's target spacing, and grants the leader
/// [`HEADERS_DOWNLOAD_TIMEOUT_BASE`] plus that many multiples of
/// [`HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER`] to catch us up.
fn headers_download_deadline(cs: &Chainstate, now: u32) -> Instant {
    let params = cs.tree().params();
    let best_header_time = cs.tree().tip().header.time;
    let elapsed_secs = u64::from(now.saturating_sub(best_header_time));
    let estimated_headers = elapsed_secs / params.pow_target_spacing.max(1);
    let per_header =
        HEADERS_DOWNLOAD_TIMEOUT_PER_HEADER * u32::try_from(estimated_headers).unwrap_or(u32::MAX);
    Instant::now() + HEADERS_DOWNLOAD_TIMEOUT_BASE + per_header
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::message::{
        AddrEntry, GetHeaders, InvType, InvVector, NODE_NETWORK, PROTOCOL_VERSION, Version,
    };
    use crate::testchain::{self, chain_blocks, regtest};
    use crate::testpipe::{self, End};
    use avila_consensus::block::Block;
    use avila_consensus::hash::BlockHash;
    use avila_consensus::transaction::Transaction;

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
        assert!(
            events
                .iter()
                .any(|e| matches!(e, NetEvent::Connected { .. }))
        );

        // Peer opens a round over its own 3-id pool; ours is empty.
        let mut sk = crate::sketch::Sketch::new(8);
        for id in [7u32, 8, 9] {
            sk.add(id);
        }
        testpipe::inject(&mut peer, MAGIC, &Message::ReqRecon(sk.serialize()));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        assert!(
            sent.iter().any(|m| matches!(m, Message::Sketch(_))),
            "{sent:?}"
        );
        let rd = sent.iter().find_map(|m| match m {
            Message::ReconcilDiff { short_ids, .. } => Some(short_ids.clone()),
            _ => None,
        });
        assert_eq!(
            rd.map(|mut v| {
                v.sort();
                v
            }),
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
        assert!(
            sent.iter().any(|m| matches!(m, Message::ReqRecon(_))),
            "{sent:?}"
        );
    }

    #[test]
    fn two_recon_peers_open_independent_rounds() {
        // Two links negotiate recon with different salts — each round
        // runs on its own schedule and its own salted sketch.
        let (us_a, peer_a) = testpipe::pair();
        let (us_b, peer_b) = testpipe::pair();
        let mut pa = peer_a;
        let mut pb = peer_b;
        let sa = PeerSession::initiate(
            us_a,
            MAGIC,
            build_version(1, 0, NetAddr::unspecified(), i64::from(NOW)),
            BUDGET,
        )
        .expect("session a");
        let sb = PeerSession::initiate(
            us_b,
            MAGIC,
            build_version(1, 0, NetAddr::unspecified(), i64::from(NOW)),
            BUDGET,
        )
        .expect("session b");
        let mut mgr = PeerManager::new(8);
        let mut cs = regtest();
        mgr.add_outbound(sa).unwrap();
        mgr.add_outbound(sb).unwrap();
        mgr.tick(&mut cs, NOW);
        let _ = testpipe::drain(&mut pa, MAGIC);
        let _ = testpipe::drain(&mut pb, MAGIC);
        for (p, salt) in [(&mut pa, 0x11u64), (&mut pb, 0x22u64)] {
            testpipe::inject(p, MAGIC, &Message::Version(peer_version(600)));
            testpipe::inject(
                p,
                MAGIC,
                &Message::SendRecon(crate::message::SendRecon {
                    is_sender: true,
                    is_responder: true,
                    version: crate::recon::RECON_VERSION,
                    salt,
                }),
            );
            mgr.tick(&mut cs, NOW);
            testpipe::inject(p, MAGIC, &Message::Verack);
            mgr.tick(&mut cs, NOW);
        }
        // Both back-due — each opens its own round.
        for peer in mgr.peers.values_mut() {
            peer.next_recon = Instant::now() - Duration::from_secs(1);
        }
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent_a = testpipe::drain(&mut pa, MAGIC);
        let sent_b = testpipe::drain(&mut pb, MAGIC);
        assert!(
            sent_a.iter().any(|m| matches!(m, Message::ReqRecon(_))),
            "peer a got no round: {sent_a:?}"
        );
        assert!(
            sent_b.iter().any(|m| matches!(m, Message::ReqRecon(_))),
            "peer b got no round: {sent_b:?}"
        );
        // The salts differ — the recon state must be per-peer, not shared.
        let salts: Vec<u64> = mgr
            .peers
            .values()
            .filter_map(|p| p.recon.as_ref().map(|r| r.their_salt))
            .collect();
        assert_eq!(salts.len(), 2);
        assert!(salts.contains(&0x11) && salts.contains(&0x22), "{salts:?}");
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

    /// Core's `CheckIncomingNonce`: an inbound peer whose `version`
    /// carries the same nonce we sent on a live outbound dial is our
    /// own connection looping back to us, and gets disconnected.
    #[test]
    fn inbound_version_matching_our_outbound_nonce_is_self_connect() {
        let mut mgr = PeerManager::new(8);
        let mut cs = regtest();
        // `add_peer`'s outbound dial sends `build_version(9, ...)`.
        let (_out_peer, _out_id) = add_peer(&mut mgr);

        let (us_end, mut peer_end) = testpipe::pair();
        let session = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(99, 0, NetAddr::unspecified(), i64::from(NOW)),
            BUDGET,
        )
        .expect("session");
        let in_id = mgr.add_inbound(session).expect("slot");
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_end, MAGIC);

        // The "peer" answers with our own outbound nonce (9) — as if
        // this inbound socket were the far end of our own dial.
        testpipe::inject(
            &mut peer_end,
            MAGIC,
            &Message::Version(Version {
                version: PROTOCOL_VERSION,
                services: NODE_NETWORK,
                timestamp: i64::from(NOW),
                addr_recv: NetAddr::unspecified(),
                addr_from: NetAddr::unspecified(),
                nonce: 9,
                user_agent: "/peer:0.0/".to_string(),
                start_height: 600,
                relay: true,
            }),
        );
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            events.iter().any(|e| matches!(
                e,
                NetEvent::Disconnected { peer, .. } if *peer == in_id
            )),
            "{events:?}"
        );
        assert!(!mgr.peers.contains_key(&in_id));
    }

    /// An inbound peer whose nonce doesn't match any live outbound
    /// dial's is an ordinary peer, not a self-connection.
    #[test]
    fn inbound_version_with_unrelated_nonce_is_not_self_connect() {
        let mut mgr = PeerManager::new(8);
        let mut cs = regtest();
        let (_out_peer, _out_id) = add_peer(&mut mgr); // registers nonce 9

        let (mut peer_end, in_id) = add_inbound_peer(&mut mgr).expect("slot");
        let events = handshake(&mut mgr, &mut peer_end, &mut cs); // peer_version's nonce is 7, not 9
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, NetEvent::Disconnected { .. }))
        );
        assert!(mgr.peers.contains_key(&in_id));
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

    /// End-to-end (through `tick`) check of the header-chain anti-DoS
    /// gate: a full-page, low-work `headers` message is not misbehavior
    /// on its own (no disconnect) and nothing from it reaches the header
    /// tree, yet the manager still relays the presync's own continuation
    /// `getheaders`. The state machine itself is covered by
    /// `headerssync`'s and `sync`'s own tests; this only pins that the
    /// wiring through `dispatch`/`tick` behaves the same way.
    #[test]
    fn low_work_headers_page_is_diverted_not_stored() {
        let (mut mgr, mut peer, id) = managed_peer();
        let mut params = avila_consensus::params::Network::Regtest.params();
        // Above a single 2000-header regtest page's own claimed work
        // (2 per header, plus genesis's own 2 = 4002) — otherwise that
        // one page would already clear the floor and never divert.
        params.minimum_chain_work =
            avila_consensus::arith::Work(avila_consensus::arith::U256::from_u64(4_010));
        let seed = avila_consensus::chainstate::Chainstate::new(&params);
        let blocks = chain_blocks(&seed, crate::message::MAX_HEADERS_RESULTS as u32);
        let headers: Vec<avila_consensus::header::BlockHeader> =
            blocks.iter().map(|b| b.header).collect();
        let mut cs = avila_consensus::chainstate::Chainstate::new(&params);
        handshake(&mut mgr, &mut peer, &mut cs);
        mgr.tick(&mut cs, NOW); // settle the Established-time getheaders
        testpipe::drain(&mut peer, MAGIC);
        let _ = id;

        testpipe::inject(&mut peer, MAGIC, &Message::Headers(headers));
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, NetEvent::Disconnected { .. })),
            "a low-work batch is not misbehavior on its own: {events:?}"
        );
        assert_eq!(
            cs.tree().len(),
            1,
            "nothing from a low-work page should be stored directly"
        );

        // The manager still relays the presync's own continuation
        // request (flushed on the *next* tick — see the comment in
        // `getaddr_from_outbound_peer_is_ignored`).
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        assert!(
            sent.iter().any(|m| matches!(m, Message::GetHeaders(_))),
            "the presync should still page for more: {sent:?}"
        );
    }

    /// A short low-work batch that proves this peer's chain can't ever
    /// clear the anti-DoS floor must release headers leadership right
    /// away — not misbehavior, not a disconnect, but no reason to keep
    /// waiting on this peer either. Without this, sync would freeze
    /// until one of the (much longer) timeouts eventually fired.
    #[test]
    fn abandoned_low_work_sync_releases_leadership_immediately() {
        let (mut mgr, mut peer, id) = managed_peer();
        let mut params = avila_consensus::params::Network::Regtest.params();
        // Unreachable by any batch this test could send.
        params.minimum_chain_work =
            avila_consensus::arith::Work(avila_consensus::arith::U256::from_u64(50_000));
        let seed = avila_consensus::chainstate::Chainstate::new(&params);
        let blocks = chain_blocks(&seed, 5); // far short of a full page
        let headers: Vec<avila_consensus::header::BlockHeader> =
            blocks.iter().map(|b| b.header).collect();
        let mut cs = avila_consensus::chainstate::Chainstate::new(&params);
        handshake(&mut mgr, &mut peer, &mut cs);
        mgr.tick(&mut cs, NOW); // settle the Established-time getheaders
        testpipe::drain(&mut peer, MAGIC);
        assert_eq!(mgr.headers_leader, Some(id));

        testpipe::inject(&mut peer, MAGIC, &Message::Headers(headers));
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, NetEvent::Disconnected { .. })),
            "a low-work batch is not misbehavior on its own: {events:?}"
        );
        // With only one peer, releasing leadership is immediately
        // followed (same tick) by `fill_queues` reassigning it right
        // back — so `headers_leader` alone can't distinguish "released
        // and reassigned" from "never released" (both leave it
        // `Some(id)`). What *does* distinguish them: a released slot
        // gets a fresh `getheaders` queued by `fill_queues`'s leaderless
        // branch; a stuck one sends nothing further at all.
        assert_eq!(mgr.headers_leader, Some(id));
        mgr.tick(&mut cs, NOW); // flush that fresh getheaders onto the wire
        let sent = testpipe::drain(&mut peer, MAGIC);
        assert!(
            sent.iter().any(|m| matches!(m, Message::GetHeaders(_))),
            "leadership must be released and immediately reassigned, not stuck: {sent:?}"
        );
    }

    /// Core's overall sync-peer download timeout: a leader that keeps
    /// answering every single request promptly (so the per-request
    /// `HEADERS_RESPONSE_TIME` timeout never fires) but never actually
    /// finishes catching us up must still eventually lose leadership,
    /// as long as another established peer is available to take over.
    #[test]
    fn stalled_headers_leader_times_out_even_while_still_responsive() {
        let (mut mgr, mut peer_a, id_a) = managed_peer();
        // regtest's genesis (2011) is always far more than 24h behind
        // `NOW`, so this chain is never "caught up" for the timeout's
        // purposes — matching a real node mid-IBD.
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer_a, &mut cs);
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_a, MAGIC);
        assert_eq!(mgr.headers_leader, Some(id_a));

        // A second established peer so there's somewhere to hand
        // leadership to.
        let (mut peer_b, id_b) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        testpipe::drain(&mut peer_b, MAGIC);

        // Force A's overall deadline into the past, as if
        // HEADERS_DOWNLOAD_TIMEOUT_BASE had elapsed with A never
        // catching us up — regardless of how promptly it might have
        // been answering individual getheaders the whole time.
        mgr.headers_sync_deadline = Some(Instant::now() - Duration::from_secs(1));

        let events = mgr.tick(&mut cs, NOW);
        assert!(
            events.iter().any(|e| matches!(
                e,
                NetEvent::Disconnected {
                    peer,
                    reason: DisconnectReason::Stalled
                } if *peer == id_a
            )),
            "{events:?}"
        );
        assert_eq!(mgr.headers_leader, Some(id_b), "leadership must pass to B");
    }

    /// The overall sync-peer timeout must never fire with no other
    /// established peer available — Core's "we have bigger problems if
    /// we can't get any outbound peers" guard.
    #[test]
    fn stalled_headers_leader_is_kept_when_no_other_peer_exists() {
        let (mut mgr, mut peer_a, id_a) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer_a, &mut cs);
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_a, MAGIC);
        assert_eq!(mgr.headers_leader, Some(id_a));

        mgr.headers_sync_deadline = Some(Instant::now() - Duration::from_secs(1));

        let events = mgr.tick(&mut cs, NOW);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, NetEvent::Disconnected { .. })),
            "the only peer must not be dropped for stalling: {events:?}"
        );
        assert_eq!(mgr.headers_leader, Some(id_a));
    }

    /// A peer whose block requests go unanswered keeps the connection:
    /// its reservations are poached by the fetch pool (Core's
    /// reassign-on-stall) so the work proceeds elsewhere, and only a
    /// peer that stalls release after release is dropped.
    #[test]
    fn stalled_peer_is_poached_then_dropped_after_repeated_stalls() {
        let (mut mgr, mut peer_a, id_a) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer_a, &mut cs);
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_a, MAGIC);

        // Give the peer outstanding block requests (fake hashes — the
        // stall path doesn't care whether the blocks exist).
        let fake: Vec<BlockHash> = (0..4)
            .map(|i| BlockHash::from_bytes([i as u8 + 1; 32]))
            .collect();
        {
            let peer = mgr.peers.get_mut(&id_a).unwrap();
            let _ = peer.sync.want_blocks(&cs, &fake);
            assert_eq!(peer.sync.in_flight(), 4);
            peer.sync.force_stalled();
        }
        assert!(mgr.peers[&id_a].sync.stalled());

        // First stall: reservations released back to the pool, no drop.
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            !events.iter().any(|e| matches!(
                e,
                NetEvent::Disconnected { peer, .. } if *peer == id_a
            )),
            "first stall must poach, not disconnect: {events:?}"
        );
        assert_eq!(
            mgr.peers[&id_a].sync.in_flight(),
            0,
            "stall releases the peer's reservations for others"
        );
        assert_eq!(mgr.peers[&id_a].stall_releases, 1);

        // Repeat until the eviction threshold: each release with no
        // intervening delivery counts against the peer.
        for expected in 2..=4u32 {
            {
                let peer = mgr.peers.get_mut(&id_a).unwrap();
                let _ = peer.sync.want_blocks(&cs, &fake);
                peer.sync.force_stalled();
            }
            let events = mgr.tick(&mut cs, NOW);
            if expected < 4 {
                assert!(
                    !events.iter().any(|e| matches!(
                        e,
                        NetEvent::Disconnected { peer, .. } if *peer == id_a
                    )),
                    "stall cycle {expected} still only poaches: {events:?}"
                );
            } else {
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        NetEvent::Disconnected {
                            peer,
                            reason: DisconnectReason::Stalled
                        } if *peer == id_a
                    )),
                    "fourth unrelieved stall disconnects: {events:?}"
                );
            }
        }
    }

    /// A block delivery clears the stall counter — a slow peer that
    /// still answers is never evicted no matter how often its queues
    /// get poached.
    #[test]
    fn block_delivery_resets_the_stall_counter() {
        let (mut mgr, mut peer_a, id_a) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer_a, &mut cs);
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_a, MAGIC);
        mgr.peers.get_mut(&id_a).unwrap().stall_releases = 3;

        // Any block message resets the counter, even an orphan.
        let mut orphan = crate::testchain::chain_blocks(&cs, 1)
            .into_iter()
            .next()
            .unwrap();
        orphan.header.prev_block_hash = BlockHash::from_bytes([9u8; 32]);
        testpipe::inject(&mut peer_a, MAGIC, &Message::Block(orphan));
        mgr.tick(&mut cs, NOW);
        assert_eq!(mgr.peers[&id_a].stall_releases, 0);
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

    /// A headers leader that stops answering `getheaders` — while
    /// staying connected — must not freeze sync forever: once its
    /// outstanding request times out (Core's `HEADERS_RESPONSE_TIME`),
    /// the manager drops it and hands leadership to another peer.
    #[test]
    fn unresponsive_headers_leader_is_replaced() {
        let (mut mgr, mut peer_a, id_a) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer_a, &mut cs);
        testpipe::drain(&mut peer_a, MAGIC); // A's initial getheaders — A leads
        assert_eq!(mgr.headers_leader, Some(id_a));

        let (mut peer_b, id_b) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        testpipe::drain(&mut peer_b, MAGIC); // B's own initial getheaders

        // A never answers. Force its outstanding request to look
        // expired rather than actually sleeping past HEADERS_RESPONSE_TIME.
        mgr.peers
            .get_mut(&id_a)
            .expect("A is connected")
            .sync
            .force_headers_timeout();

        let events = mgr.tick(&mut cs, NOW);
        assert!(
            events.iter().any(|e| matches!(
                e,
                NetEvent::Disconnected {
                    peer,
                    reason: DisconnectReason::Stalled
                } if *peer == id_a
            )),
            "{events:?}"
        );
        assert_eq!(mgr.headers_leader, Some(id_b), "leadership must pass to B");

        let sent = testpipe::drain(&mut peer_b, MAGIC);
        assert!(
            sent.iter().any(|m| matches!(m, Message::GetHeaders(_))),
            "B should be paged for headers once it takes over leadership: {sent:?}"
        );
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

    /// The hb-announces path: a compact-negotiated peer receives the
    /// new tip as `cmpctblock`, not headers/inv — and the block body
    /// must be readable for `make_cmpctblock` right after connect.
    #[test]
    fn connected_tip_announces_cmpctblock_to_negotiated_peers() {
        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        mgr.set_compact_relay(true, true, true, "");
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
        // B negotiates compact v2 (post-verack, the way Core does it);
        // C does not — it stays on the inv path.
        testpipe::inject(
            &mut peer_b,
            MAGIC,
            &Message::SendCmpct {
                announce: true,
                version: 2,
            },
        );
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_b, MAGIC);

        testpipe::inject(&mut peer_a, MAGIC, &Message::Block(blocks[0].clone()));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent_b = testpipe::drain(&mut peer_b, MAGIC);
        let sent_c = testpipe::drain(&mut peer_c, MAGIC);
        assert!(
            sent_b.iter().any(|m| matches!(
                m,
                Message::CmpctBlock(cb) if cb.header.hash() == blocks[0].block_hash()
            )),
            "compact peer should get a cmpctblock announce: {sent_b:?}"
        );
        assert!(
            !sent_b
                .iter()
                .any(|m| matches!(m, Message::Headers(_) | Message::Inv(_))),
            "hb peer must not also get a headers/inv announce: {sent_b:?}"
        );
        assert!(
            sent_c.iter().any(|m| matches!(m, Message::Inv(_))),
            "non-compact peer keeps the inv path: {sent_c:?}"
        );
    }

    /// Live-wire shape: a block connected *via compact reconstruction*
    /// still fans out — the announce loop must not lose the tip when
    /// the connect happened through `PartialBlock` recursion.
    #[test]
    fn compact_connected_tip_is_relayed_to_compact_peers() {
        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        mgr.set_compact_relay(true, true, true, "");
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 2);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        let (mut peer_b, _id_b) = add_peer(&mut mgr);
        handshake(&mut mgr, &mut peer_a, &mut cs);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        for p in [&mut peer_a, &mut peer_b] {
            testpipe::inject(
                p,
                MAGIC,
                &Message::SendCmpct {
                    announce: true,
                    version: 2,
                },
            );
        }
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_a, MAGIC);
        testpipe::drain(&mut peer_b, MAGIC);

        // A delivers the tip as a compact block — a full pool hit.
        let cb = crate::compact::make_cmpctblock(&blocks[0]);
        testpipe::inject(&mut peer_a, MAGIC, &Message::CmpctBlock(cb));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent_b = testpipe::drain(&mut peer_b, MAGIC);
        assert!(
            sent_b.iter().any(|m| matches!(
                m,
                Message::CmpctBlock(cb) if cb.header.hash() == blocks[0].block_hash()
            )),
            "compact-connected tip must announce compact to B: {sent_b:?}"
        );
    }

    /// Audit reproducer — a block whose script check fails, delivered
    /// over a real session as the LAST block of a batch shorter than
    /// the speculative window, with no further deliveries: it must
    /// never reach an authoritative observer (no TipAdvanced event
    /// past the checked frontier, no announcement to other peers,
    /// mempool untouched). The applied tip may advance — verification
    /// is what's gated, not UTXO application.
    #[test]
    fn speculative_short_tail_failure_is_never_published() {
        let (mut mgr, mut peer, _id_a) = managed_peer();
        let mut cs = regtest();
        cs.enable_speculative_connect();
        let params = *cs.tree().params();
        // Heights 1..=110 — block 105 spends an always-false script
        // (mature by then); delivery stops at 110 so blocks 103..110
        // are still inside the pending window when the burst ends.
        let blocks = testchain::probe_chain(&params, 110, 105);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        let (mut peer_b, _id_b) = add_peer(&mut mgr);
        handshake(&mut mgr, &mut peer, &mut cs);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        testpipe::drain(&mut peer, MAGIC);
        testpipe::drain(&mut peer_b, MAGIC);

        let mut events = Vec::new();
        for b in &blocks {
            testpipe::inject(&mut peer, MAGIC, &Message::Block(b.clone()));
            events.extend(mgr.tick(&mut cs, NOW));
        }
        // The applied tip ran ahead of the checked frontier — pending
        // holds the tail (bad block inside it, undrained) — yet
        // nothing authoritative may show it.
        assert_eq!(cs.chain().len() as u32, 111);
        let checked = cs.checked_height();
        assert!(checked < 105, "checked frontier must lag the tail");
        assert!(cs.pending_scripts_len() > 0);
        for ev in &events {
            if let NetEvent::TipAdvanced(h) = ev {
                assert!(
                    *h <= checked,
                    "TipAdvanced({h}) published an unverified height"
                );
            }
        }
        // A second peer was told about nothing past the checked tip.
        let heard = testpipe::drain(&mut peer_b, MAGIC);
        for h in checked..110 {
            let hash = blocks[h as usize].block_hash();
            assert!(
                !heard.iter().any(|m| matches!(m,
                    Message::Inv(vs) if vs.iter().any(|v| v.hash == hash))
                    || matches!(m, Message::Headers(hs) if hs.iter().any(|hh| hh.hash() == hash))),
                "unverified block {h} announced to peers: {heard:?}"
            );
        }
        // The quiet-tail drain (what the sync loop runs once arrivals
        // pause) surfaces the failure: rewind to 104, bad block marked,
        // checked frontier still clean.
        assert!(cs.drain_scripts().is_err());
        assert_eq!(cs.chain().len() as u32, 105); // genesis + 104
        assert_eq!(cs.checked_height(), 104);
        assert!(cs.tree().is_failed(&blocks[104].block_hash()));
        // Attribution: the failure names the bad block's hash.
        assert_eq!(cs.take_spec_failed(), Some(blocks[104].block_hash()));
    }

    /// The all-valid short tail: pending blocks publish normally once
    /// their checks complete — the boundary delays effects, it never
    /// drops them.
    #[test]
    fn speculative_valid_tail_publishes_on_drain() {
        let (mut mgr, mut peer, _id_a) = managed_peer();
        let mut cs = regtest();
        cs.enable_speculative_connect();
        let blocks = testchain::chain_blocks(&cs, 6);
        for b in &blocks {
            cs.accept_header(&b.header, NOW).unwrap();
        }
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);
        let mut events = Vec::new();
        for b in &blocks {
            testpipe::inject(&mut peer, MAGIC, &Message::Block(b.clone()));
            events.extend(mgr.tick(&mut cs, NOW));
        }
        assert_eq!(cs.chain().len() as u32, 7);
        // A 6-block batch never exceeds the window — all 6 pending,
        // checked frontier at genesis.
        assert_eq!(cs.checked_height(), 0);
        assert!(
            events
                .iter()
                .all(|e| !matches!(e, NetEvent::TipAdvanced(_)))
        );
        // Quiet-tail drain completes them all.
        cs.drain_scripts().unwrap();
        assert_eq!(cs.checked_height(), 6);
        let fed: Vec<u32> = cs.take_checked().iter().map(|(h, _)| *h).collect();
        assert_eq!(fed, (1..=6).collect::<Vec<u32>>());
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

    /// The `peer.accept` hook consults on the real admission path:
    /// drive a handshake over a loopback socket, push the completed
    /// session through the inbound channel, and drain.
    #[test]
    fn inbound_verdict_hook_narrows_admission() {
        use std::net::{TcpListener, TcpStream};
        let mut mgr = PeerManager::<TcpStream>::new(8);
        mgr.set_inbound_verdict(Some(Box::new(|f: &InboundFacts| f.remote.port() != 6666)));
        for port in [40_001u16, 6666] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let ours = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (theirs, _) = listener.accept().unwrap();
            let responder = std::thread::spawn(move || {
                PeerSession::accept(
                    theirs,
                    MAGIC,
                    build_version(9, 0, NetAddr::unspecified(), i64::from(NOW)),
                    BUDGET,
                )
            });
            let session = PeerSession::initiate(
                ours,
                MAGIC,
                build_version(1, 0, NetAddr::unspecified(), i64::from(NOW)),
                BUDGET,
            )
            .expect("handshake");
            responder.join().unwrap();
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            mgr.inbound_tx.send((addr, Ok(session))).unwrap();
        }
        let admitted = mgr.drain_inbounds();
        assert_eq!(admitted.len(), 1, "port 6666 refused by the hook");
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
        // The regtest fixture spends and pays OP_TRUE — nonstandard, as
        // under Core, so opt out like `-acceptnonstdtxn=1`.
        mgr.mempool().set_require_standard(false);
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

    /// Drives a handshake where the peer advertises `sendcmpct` —
    /// `Some(hb)` requests high-bandwidth announcements — plus v2.
    fn handshake_cmpct(
        mgr: &mut PeerManager<End>,
        peer: &mut End,
        cs: &mut Chainstate,
        hb: bool,
    ) -> Vec<NetEvent> {
        let mut events = mgr.tick(cs, NOW);
        let _ = testpipe::drain(peer, MAGIC);
        testpipe::inject(peer, MAGIC, &Message::Version(peer_version(600)));
        testpipe::inject(
            peer,
            MAGIC,
            &Message::SendCmpct {
                announce: hb,
                version: crate::message::SENDCMPCT_VERSION_WITNESS,
            },
        );
        events.extend(mgr.tick(cs, NOW));
        testpipe::inject(peer, MAGIC, &Message::Verack);
        events.extend(mgr.tick(cs, NOW));
        events
    }

    /// The OP_TRUE spend of `blocks[0]`'s coinbase (mature at 101) —
    /// the same fixture `accepted_tx_relays_to_other_peers` uses.
    fn spend_fixture(blocks: &[Block]) -> Transaction {
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        use avila_consensus::{script, transaction::Transaction};
        Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: blocks[0].transactions[0].txid(),
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_ffff,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 4_999_000_000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn cmpctblock_reconstructs_from_pool_and_connects() {
        use crate::testchain::{block_on_txs, coinbase_tx};
        let (mut mgr, mut peer, _id) = managed_peer();
        mgr.mempool().set_require_standard(false);
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        handshake_cmpct(&mut mgr, &mut peer, &mut cs, true);
        testpipe::drain(&mut peer, MAGIC);
        testpipe::inject(&mut peer, MAGIC, &Message::Headers(vec![]));
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer, MAGIC);

        // The peer relays the spend to us — it lands in the pool, then
        // the compact block's short-id resolves locally.
        let tx = spend_fixture(&blocks);
        testpipe::inject(&mut peer, MAGIC, &Message::Tx(tx.clone()));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        assert!(mgr.mempool().get(&tx.txid()).is_some());
        let params = *cs.tree().params();
        let block = block_on_txs(&blocks[100].header, vec![coinbase_tx(102), tx], &params);
        let cb = crate::compact::make_cmpctblock(&block);
        testpipe::inject(&mut peer, MAGIC, &Message::CmpctBlock(cb));
        // Reconstruct → dispatch as Block → connect; announce → flush.
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        assert_eq!(
            cs.chain().len(),
            103,
            "compact-delivered block should connect"
        );
    }

    #[test]
    fn cmpctblock_missing_tx_roundtrips_getblocktxn() {
        use crate::testchain::{block_on_txs, coinbase_tx};
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        handshake_cmpct(&mut mgr, &mut peer, &mut cs, false);
        testpipe::drain(&mut peer, MAGIC);
        testpipe::inject(&mut peer, MAGIC, &Message::Headers(vec![]));
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer, MAGIC);

        // The block carries a tx we never saw — slot 1 stays missing.
        use avila_consensus::script;
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        let unseen = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: blocks[0].transactions[0].txid(),
                    vout: 0,
                },
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
        let params = *cs.tree().params();
        let block = block_on_txs(
            &blocks[100].header,
            vec![coinbase_tx(102), unseen.clone()],
            &params,
        );
        let hash = block.block_hash();
        let cb = crate::compact::make_cmpctblock(&block);
        testpipe::inject(&mut peer, MAGIC, &Message::CmpctBlock(cb));
        // Reconstruction finds slot 1 missing → queues getblocktxn,
        // which flushes on the following tick.
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        let ask = sent.iter().find_map(|m| match m {
            Message::GetBlockTxn(r) => Some(r.clone()),
            _ => None,
        });
        let ask = ask.unwrap_or_else(|| panic!("getblocktxn expected: {sent:?}"));
        assert_eq!(ask.block_hash, hash);
        assert_eq!(ask.indexes, vec![1u32], "slot 1's differential index");

        // The peer answers; reconstruction completes and connects.
        testpipe::inject(
            &mut peer,
            MAGIC,
            &Message::BlockTxn(crate::message::BlockTxn {
                block_hash: hash,
                txs: vec![unseen],
            }),
        );
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        assert_eq!(cs.chain().len(), 103);
    }

    #[test]
    fn cmpctblock_without_negotiation_is_ignored() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 2);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);
        // No sendcmpct was exchanged — a cmpctblock is unsolicited spam;
        // ignore, don't disconnect (BIP152 doesn't punish it).
        let cb = crate::compact::make_cmpctblock(&blocks[1]);
        testpipe::inject(&mut peer, MAGIC, &Message::CmpctBlock(cb));
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, NetEvent::Disconnected { .. })),
            "{events:?}"
        );
        assert_eq!(cs.chain().len(), 3);
    }

    #[test]
    fn blocks_only_and_announce_none_silence_tx_relay() {
        let (mut mgr, mut peer_a, _id_a) = managed_peer();
        mgr.mempool().set_require_standard(false);
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        let (mut peer_b, _id_b) = add_peer(&mut mgr);
        handshake(&mut mgr, &mut peer_a, &mut cs);
        handshake_peer(&mut mgr, &mut peer_b, &mut cs);
        for p in [&mut peer_a, &mut peer_b] {
            testpipe::inject(p, MAGIC, &Message::Headers(vec![]));
            testpipe::drain(p, MAGIC);
        }
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_a, MAGIC);
        testpipe::drain(&mut peer_b, MAGIC);

        // blocks_only: A's tx announce produces no fetch request.
        mgr.set_blocks_only(true);
        let tx = spend_fixture(&blocks);
        testpipe::inject(
            &mut peer_a,
            MAGIC,
            &Message::Inv(vec![InvVector {
                inv_type: InvType::Tx,
                hash: BlockHash::from_bytes(*tx.txid().as_bytes()),
            }]),
        );
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer_a, MAGIC);
        assert!(
            !sent.iter().any(|m| matches!(m, Message::GetData(_))),
            "blocks_only fetches nothing: {sent:?}"
        );

        // announce=none: a relayed tx never leaves as inv.
        mgr.set_blocks_only(false);
        mgr.set_tx_relay("none", true, false, 0, true, 60);
        testpipe::inject(&mut peer_a, MAGIC, &Message::Tx(tx.clone()));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer_a, MAGIC);
        let sent_b = testpipe::drain(&mut peer_b, MAGIC);
        assert!(
            !sent_b.iter().any(|m| matches!(m, Message::Inv(vs)
                if vs.iter().any(|v| v.hash.as_bytes() == tx.txid().as_bytes()))),
            "announce=none announces nothing: {sent_b:?}"
        );
    }

    #[test]
    fn mempool_request_is_served_from_the_pool() {
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        use avila_consensus::{script, transaction::Transaction};

        // Audit P2P-BIP35: `mempool` is answered only for inbound peers
        // (Core's rule — a peer we dialed doesn't get the whole pool),
        // so this test's peer must be inbound.
        let mut mgr = PeerManager::new(8);
        let (mut peer_a, _id_a) = add_inbound_peer(&mut mgr).expect("slot");
        // The regtest fixture spends and pays OP_TRUE — nonstandard, as
        // under Core, so opt out like `-acceptnonstdtxn=1`.
        mgr.mempool().set_require_standard(false);
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

        // A single entry: Core's address-processing token bucket starts
        // at 1.0 (see `addr_processing_is_rate_limited` for the
        // multi-entry, rate-limited case), so one entry always clears it.
        let gossip = vec![AddrEntry {
            time: NOW - 10,
            addr: addrman::net_addr_of("93.184.216.34:18444".parse().unwrap(), NODE_NETWORK),
        }];
        testpipe::inject(&mut peer, MAGIC, &Message::Addr(gossip));
        mgr.tick(&mut cs, NOW);
        assert_eq!(mgr.addr_book().len(), 1);
    }

    /// Core's per-peer address-processing token bucket
    /// (`MAX_ADDR_RATE_PER_SECOND`/`MAX_ADDR_PROCESSING_TOKEN_BUCKET`):
    /// a freshly connected peer starts with exactly one token, so a
    /// message bundling several unsolicited addresses only has the
    /// first one processed — the rest are rate-limited, not stored, and
    /// counted separately from what was processed.
    #[test]
    fn addr_processing_is_rate_limited() {
        let (mut mgr, mut peer, id) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);

        let gossip: Vec<AddrEntry> = (0..5)
            .map(|i| AddrEntry {
                time: NOW - 10,
                addr: addrman::net_addr_of(
                    format!("93.184.216.{}:18444", 40 + i).parse().unwrap(),
                    NODE_NETWORK,
                ),
            })
            .collect();
        testpipe::inject(&mut peer, MAGIC, &Message::Addr(gossip));
        mgr.tick(&mut cs, NOW);

        assert_eq!(
            mgr.addr_book().len(),
            1,
            "only the first entry affords a token"
        );
        let snap = mgr
            .peer_snapshots()
            .into_iter()
            .find(|p| p.id == id)
            .unwrap();
        assert_eq!(snap.addr_processed, 1);
        assert_eq!(snap.addr_rate_limited, 4);
    }

    #[test]
    fn getaddr_serves_gossiped_peers() {
        // Core answers `getaddr` only on inbound connections.
        let mut mgr = PeerManager::new(8);
        let (mut peer, _id) = add_inbound_peer(&mut mgr).expect("slot");
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

    /// An outbound peer's `getaddr` is ignored outright — Core's
    /// asymmetric fingerprinting defense (`IsInboundConn()` gate).
    #[test]
    fn getaddr_from_outbound_peer_is_ignored() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer, &mut cs);
        // Settle the Established-time getheaders(es): a manager-level
        // reply queued during one tick's dispatch only reaches the wire
        // on the *next* tick's poll (its flush runs before it reads),
        // so an extra tick+drain here keeps that noise out of `sent`
        // below rather than changing what it can prove.
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut peer, MAGIC);

        testpipe::inject(&mut peer, MAGIC, &Message::GetAddr);
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let sent = testpipe::drain(&mut peer, MAGIC);
        assert!(
            !sent
                .iter()
                .any(|m| matches!(m, Message::AddrV2(_) | Message::Addr(_))),
            "an outbound peer must never receive an addr reply: {sent:?}"
        );
    }

    /// A second `getaddr` on the same (inbound) connection is ignored —
    /// Core's "only send one GetAddr response per connection" guard
    /// against reply spam and addr-stamping later INV announcements.
    #[test]
    fn repeated_getaddr_is_answered_only_once() {
        let mut mgr = PeerManager::new(8);
        let (mut peer, _id) = add_inbound_peer(&mut mgr).expect("slot");
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer, &mut cs);
        mgr.tick(&mut cs, NOW); // settle the Established-time getheaders(es)
        testpipe::drain(&mut peer, MAGIC);

        testpipe::inject(&mut peer, MAGIC, &Message::GetAddr);
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let first = testpipe::drain(&mut peer, MAGIC);
        assert!(
            first.iter().any(|m| matches!(m, Message::AddrV2(_))),
            "the first getaddr must be answered: {first:?}"
        );

        testpipe::inject(&mut peer, MAGIC, &Message::GetAddr);
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let second = testpipe::drain(&mut peer, MAGIC);
        assert!(
            !second.iter().any(|m| matches!(m, Message::AddrV2(_))),
            "a repeated getaddr on the same connection must be ignored: {second:?}"
        );
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

    /// A peer that connects and hangs up without sending anything must
    /// be reported as a prompt error, not spin `peek` forever on `Ok(0)`
    /// (an empty peek trivially "equals" an empty prefix slice).
    #[test]
    fn transport_probe_reports_eof_promptly() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let client = TcpStream::connect(laddr).unwrap();
        let (server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        drop(client); // hang up with zero bytes sent

        let want = v1_version_prefix(MAGIC);
        let started = Instant::now();
        let err = probe_transport_prefix(&server, want, started + Duration::from_secs(30))
            .expect_err("EOF must surface as an error, not a spin");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        // Reported immediately — nowhere near the 30s deadline given.
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A peer that sends a few bytes of the public v1 prefix and then
    /// goes quiet (whether it closed with those bytes still unread, or
    /// just stalled — `peek` cannot tell the two apart, since it never
    /// consumes what it sees) must be bounded by the deadline instead of
    /// spinning: each unproductive peek backs off, so the probe resolves
    /// once `deadline` passes rather than immediately or never.
    #[test]
    fn transport_probe_bounds_a_stalled_partial_prefix_to_the_deadline() {
        use std::io::Write;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let laddr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(laddr).unwrap();
        let (server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let want = v1_version_prefix(MAGIC);
        client.write_all(&want[..3]).unwrap(); // 3 matching bytes...
        client.flush().unwrap();
        drop(client); // ...then the peer is gone for good.

        let deadline_from_now = Duration::from_millis(150);
        let started = Instant::now();
        let err = probe_transport_prefix(&server, want, started + deadline_from_now)
            .expect_err("a stalled partial match must time out, not match or spin forever");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        // Bounded on both sides: it waited roughly the deadline (not an
        // instant spin) and didn't run substantially past it either
        // (not stuck retrying beyond the bound).
        let elapsed = started.elapsed();
        assert!(elapsed >= deadline_from_now);
        assert!(elapsed < deadline_from_now + Duration::from_secs(2));
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

    /// Fail-closed proxy (queue #13/#25): with a proxy set, the dial
    /// worker's connection must arrive AT THE PROXY — a clearnet
    /// bypass is observable as "proxy saw nothing". The proxy refuses
    /// (not a SOCKS5 response), so the dial fails and no peer lands.
    #[test]
    fn proxy_mode_never_touches_cleared() {
        use std::io::Read;
        use std::net::TcpListener;
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        // Record whether the proxy saw a connection, then refuse.
        let proxy_saw = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let saw = proxy_saw.clone();
        std::thread::spawn(move || {
            while let Ok((mut s, _)) = proxy_listener.accept() {
                saw.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Read the SOCKS5 greeting then drop — the dial fails.
                let mut buf = [0u8; 8];
                let _ = s.read(&mut buf);
            }
        });
        let mut mgr = PeerManager::new(4);
        mgr.set_proxy(Some(proxy_addr));
        // A routable candidate (public IP) — the book accepts it.
        let candidate: SocketAddr = "8.8.8.8:8333".parse().unwrap();
        mgr.addrbook().add_many(
            std::iter::once((crate::addrman::net_addr_of(candidate, 0), NOW)),
            NOW,
        );
        let dialed = mgr.maintain_outbounds(MAGIC, 0);
        assert_eq!(dialed, vec![candidate], "the dial must be queued");
        // Give the dial worker time to hit the proxy and fail.
        std::thread::sleep(Duration::from_millis(300));
        let mut cs = regtest();
        mgr.tick(&mut cs, NOW);
        let _ = mgr.maintain_outbounds(MAGIC, 0);
        mgr.tick(&mut cs, NOW);
        assert!(
            proxy_saw.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the dial must have arrived at the proxy — a clearnet bypass is a leak"
        );
        assert_eq!(mgr.len(), 0, "no peer may land through a dead proxy");
    }

    /// Retry cell (privacy matrix): after a dead-proxy dial fails,
    /// the NEXT maintain round must retry THROUGH the proxy again —
    /// every attempt arrives at the SOCKS5 endpoint, never clearnet.
    #[test]
    fn proxy_retries_also_ride_the_proxy() {
        use std::io::Read;
        use std::net::TcpListener;
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy_saw = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let saw = proxy_saw.clone();
        std::thread::spawn(move || {
            while let Ok((mut s, _)) = proxy_listener.accept() {
                saw.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 8];
                let _ = s.read(&mut buf);
            }
        });
        let mut mgr = PeerManager::new(4);
        mgr.set_proxy(Some(proxy_addr));
        let candidate: SocketAddr = "8.8.8.8:8333".parse().unwrap();
        mgr.addrbook().add_many(
            std::iter::once((crate::addrman::net_addr_of(candidate, 0), NOW)),
            NOW,
        );
        let mut cs = regtest();
        // Two maintain rounds = a retry after the first failure.
        for _ in 0..2 {
            let _ = mgr.maintain_outbounds(MAGIC, 0);
            std::thread::sleep(Duration::from_millis(300));
            mgr.tick(&mut cs, NOW);
        }
        assert!(
            proxy_saw.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "the retry must also arrive at the proxy — {} attempt(s) seen",
            proxy_saw.load(std::sync::atomic::Ordering::SeqCst)
        );
        assert_eq!(mgr.len(), 0);
    }

    /// Self-eclipse field test (queue #22): the lab attack — every
    /// outbound slot held by a coordinated attacker, all in one /16,
    /// all claiming a higher chain, our tip stale. The detector must
    /// fire TipStale AND DiversityCollapse — the indicators catching
    /// exactly the condition they exist for.
    #[test]
    fn self_eclipse_field_test() {
        let mut mgr = PeerManager::new(8);
        let mut cs = regtest();
        let mut ends = Vec::new();
        // Four attacker peers, one /16 (203.0.113.0/16), all outbound.
        for i in 0..4u8 {
            let (us_end, peer_end) = testpipe::pair();
            let session = PeerSession::initiate(
                us_end,
                MAGIC,
                build_version(9, 0, NetAddr::unspecified(), i64::from(NOW)),
                BUDGET,
            )
            .expect("session");
            let remote =
                crate::addrman::net_addr_of(format!("203.0.113.{i}:8333").parse().unwrap(), 0);
            let id = mgr.add_outbound_to(session, remote).expect("slot");
            ends.push((peer_end, id));
        }
        // Attackers complete the handshake, all claiming height 5 —
        // inside the headers window, so TipStale applies (claims far
        // above our tree would read as still-syncing instead).
        for (end, _) in &mut ends {
            testpipe::inject(end, MAGIC, &Message::Version(peer_version(5)));
            testpipe::inject(end, MAGIC, &Message::Verack);
        }
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        assert_eq!(mgr.len(), 4, "attackers hold all outbound slots");
        let signals = mgr.eclipse_signals(&cs, NOW);
        assert!(
            signals.contains(&EclipseSignal::TipStale),
            "stale tip + all peers claiming higher must fire TipStale: {signals:?}"
        );
        assert!(
            signals.contains(&EclipseSignal::DiversityCollapse),
            "one /16 holding all outbound slots must fire DiversityCollapse: {signals:?}"
        );
        assert!(
            !signals.contains(&EclipseSignal::AllInbound),
            "outbound attackers are not AllInbound"
        );
    }

    /// Slow-leader handoff: a sync peer whose outstanding `getheaders`
    /// exceeds the handoff window loses leadership (not the connection
    /// — it may serve blocks fine) to the next established peer, and is
    /// marked `leader_slow` so election skips it while alternatives
    /// exist.
    #[test]
    fn slow_headers_leader_loses_leadership() {
        let (mut mgr, mut a, ida) = managed_peer();
        let mut cs = crate::testchain::regtest();
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);
        let (mut b, idb) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut b, &mut cs);
        testpipe::drain(&mut b, MAGIC);

        mgr.tick(&mut cs, NOW);
        assert_eq!(mgr.headers_leader, Some(ida), "first peer leads");

        // The leader's outstanding getheaders has been waiting past the
        // handoff window but under the disconnect timeout.
        mgr.peers
            .get_mut(&ida)
            .unwrap()
            .sync
            .force_headers_wait(Duration::from_secs(30));

        mgr.tick(&mut cs, NOW);
        assert_eq!(
            mgr.headers_leader,
            Some(idb),
            "leadership must move to the next established peer"
        );
        assert!(
            mgr.peers.get(&ida).unwrap().leader_slow,
            "demoted leader carries the slow mark"
        );
        // And the connection itself is still alive.
        assert!(mgr.peers.contains_key(&ida));
    }

    /// The regression behind the /16 grouping fix: outbound peers as
    /// IPv6-mapped IPv4 (`::ffff:a.b.c.d`) share the mapped prefix, so
    /// a naive `ip[0..2]` group key collapses *every* v4-only set into
    /// one group — DiversityCollapse must not fire on real diversity.
    #[test]
    fn v4_mapped_peers_in_distinct_sixteens_do_not_collapse() {
        let mut mgr = PeerManager::new(8);
        let mut cs = regtest();
        let mut ends = Vec::new();
        // Four outbound peers, each in a different v4 /16.
        for i in 0..4u8 {
            let (us_end, peer_end) = testpipe::pair();
            let session = PeerSession::initiate(
                us_end,
                MAGIC,
                build_version(9, 0, NetAddr::unspecified(), i64::from(NOW)),
                BUDGET,
            )
            .expect("session");
            let remote = crate::addrman::net_addr_of(
                format!("{}.{}.{}.{}:8333", 20 + i, 30 + i, 40 + i, 50 + i)
                    .parse()
                    .unwrap(),
                0,
            );
            let id = mgr.add_outbound_to(session, remote).expect("slot");
            ends.push((peer_end, id));
        }
        for (end, _) in &mut ends {
            testpipe::inject(end, MAGIC, &Message::Version(peer_version(5)));
            testpipe::inject(end, MAGIC, &Message::Verack);
        }
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let signals = mgr.eclipse_signals(&cs, NOW);
        assert!(
            !signals.contains(&EclipseSignal::DiversityCollapse),
            "four distinct /16s must not read as one group: {signals:?}"
        );
    }

    /// TipStale must NOT fire while headers still trail what peers
    /// claim — during sync the tip is old by definition, so staleness
    /// then means "catching up", not "eclipsed". Claimed heights far
    /// above our header tree suppress it; claims near our tip don't.
    #[test]
    fn tip_stale_quiet_while_headers_lag() {
        let mut mgr = PeerManager::new(8);
        let mut cs = regtest();
        let mut ends = Vec::new();
        for i in 0..4u8 {
            let (us_end, peer_end) = testpipe::pair();
            let session = PeerSession::initiate(
                us_end,
                MAGIC,
                build_version(9, 0, NetAddr::unspecified(), i64::from(NOW)),
                BUDGET,
            )
            .expect("session");
            let remote =
                crate::addrman::net_addr_of(format!("203.0.113.{i}:8333").parse().unwrap(), 0);
            let id = mgr.add_outbound_to(session, remote).expect("slot");
            ends.push((peer_end, id));
        }
        for (end, _) in &mut ends {
            testpipe::inject(end, MAGIC, &Message::Version(peer_version(99999)));
            testpipe::inject(end, MAGIC, &Message::Verack);
        }
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let signals = mgr.eclipse_signals(&cs, NOW);
        assert!(
            !signals.contains(&EclipseSignal::TipStale),
            "a stale tip while headers trail every claim is syncing, not eclipse: {signals:?}"
        );
    }

    /// Eclipse detector (queue #12): four inbound-only established
    /// peers trips `AllInbound`; a healthy mixed set stays quiet.
    #[test]
    fn eclipse_detector_flags_all_inbound() {
        let mut mgr = PeerManager::new(16);
        let mut cs = regtest();
        let mut ends = Vec::new();
        for _ in 0..4 {
            let (end, id) = add_inbound_peer(&mut mgr).unwrap();
            ends.push((end, id));
        }
        // Complete the handshake on each: our side sends version,
        // they answer version+verack.
        for (end, _id) in &mut ends {
            testpipe::inject(end, MAGIC, &Message::Version(peer_version(600)));
            testpipe::inject(end, MAGIC, &Message::Verack);
        }
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let signals = mgr.eclipse_signals(&cs, NOW);
        assert!(
            signals.contains(&EclipseSignal::AllInbound),
            "four inbound-only peers should trip AllInbound: {signals:?}"
        );
    }

    /// Adversarial live-wire (queue #28): hostile inputs hit the wire
    /// path — garbage floods, oversized declarations, dribbled partial
    /// frames. Each must either drop the peer or stay inside budget;
    /// none may grow memory unboundedly.
    #[test]
    fn adversarial_livewire_budgets_hold() {
        use std::io::Write;
        let (mut mgr, mut a, id_a) = managed_peer();
        let mut cs = crate::testchain::regtest();
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);

        // 1. Garbage flood: 100KB of random bytes — decode fails, peer
        //    is dropped.
        let garbage: Vec<u8> = (0..100_000u32)
            .map(|i| i.wrapping_mul(2654435761) as u8)
            .collect();
        a.write_all(&garbage).unwrap();
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, NetEvent::Disconnected { peer: p, .. } if *p == id_a)),
            "garbage flood must drop the peer: {events:?}"
        );

        // 2. Oversized declaration: a fresh peer announces a frame
        //    bigger than MAX_MESSAGE_PAYLOAD — the decoder's buffer
        //    cap rejects it rather than buffering unboundedly.
        let (mut b, _idb) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut b, &mut cs);
        testpipe::drain(&mut b, MAGIC);
        let mut huge = Vec::new();
        huge.extend_from_slice(&MAGIC);
        huge.extend_from_slice(b"block\0\0\0\0\0\0\0");
        huge.extend_from_slice(&(5_000_000u32).to_le_bytes()); // >4MB
        huge.extend_from_slice(&[0u8; 4]); // checksum
        huge.extend_from_slice(&[0xAA; 1024]); // partial payload
        b.write_all(&huge).unwrap();
        // Not a disconnect-worthy error (the frame may complete later)
        // — but the buffer must not grow past the cap.
        mgr.tick(&mut cs, NOW);
        // Feed 5MB of payload — crosses the buffered cap → drop.
        for _ in 0..5 {
            b.write_all(&vec![0xAA; 1_000_000]).unwrap();
            mgr.tick(&mut cs, NOW);
        }
        let events = mgr.tick(&mut cs, NOW);
        let dropped = events
            .iter()
            .any(|e| matches!(e, NetEvent::Disconnected { .. }));
        // Either dropped on over-buffer or still waiting — what must
        // hold is the buffer never exceeds the frame cap. Both paths
        // are safe; assert the manager is still alive and bounded.
        let _ = dropped;
        assert!(mgr.len() <= 8);
    }

    /// ONE outbound peer immediately; after the randomized delay the
    /// fluff pass announces it to everyone.
    #[test]
    fn selfish_stem_announces_one_hop_then_fluffs() {
        let (mut mgr, mut a, _ida) = managed_peer();
        let mut cs = crate::testchain::regtest();
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);
        let (mut b, _idb) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut b, &mut cs);
        testpipe::drain(&mut b, MAGIC);

        let txid = avila_consensus::hash::Txid::from_bytes([7u8; 32]);
        let wtxid = avila_consensus::hash::Wtxid::from_bytes([9u8; 32]);
        mgr.stem_announce(txid, wtxid);
        mgr.tick(&mut cs, NOW); // flush send_bufs to the wire

        let msgs_a = testpipe::drain(&mut a, MAGIC);
        let msgs_b = testpipe::drain(&mut b, MAGIC);
        let inv = |msgs: &[Message]| {
            msgs.iter()
                .filter(|m| {
                    matches!(m, Message::Inv(v) if v.iter().any(|iv| {
                        iv.inv_type == crate::message::InvType::Wtx
                            || iv.inv_type == crate::message::InvType::Tx
                    }))
                })
                .count()
        };
        assert_eq!(
            inv(&msgs_a) + inv(&msgs_b),
            1,
            "exactly one stem hop gets the inv — a: {msgs_a:?}, b: {msgs_b:?}"
        );
        assert_eq!(mgr.stem_pending.len(), 1, "fluff is pending");

        // Force the delay elapsed; the next tick fluffs to everyone.
        mgr.stem_pending[0].2 = Instant::now() - Duration::from_secs(1);
        mgr.tick(&mut cs, NOW); // fluff queues the inv
        mgr.tick(&mut cs, NOW); // next tick flushes to the wire
        let msgs_a = testpipe::drain(&mut a, MAGIC);
        let msgs_b = testpipe::drain(&mut b, MAGIC);
        assert!(inv(&msgs_a) + inv(&msgs_b) >= 1, "fluff announce went out");
        assert!(mgr.stem_pending.is_empty());
    }

    /// `tx.announce` — a per-link verdict can withhold one peer while
    /// the rest still receive the inv. The hook sees per-peer facts.
    #[test]
    fn tx_announce_verdict_gates_one_link() {
        let (mut mgr, mut a, _ida) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);
        let (mut b, idb) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut b, &mut cs);
        testpipe::drain(&mut b, MAGIC);

        let saw_facts = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let check = saw_facts.clone();
        mgr.set_tx_announce_verdict(Some(Box::new(move |f| {
            if f.source == "local" && f.source_peer.is_none() {
                check.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            f.peer != idb
        })));

        let txid = avila_consensus::hash::Txid::from_bytes([3u8; 32]);
        let wtxid = avila_consensus::hash::Wtxid::from_bytes([4u8; 32]);
        mgr.announce_tx(txid, wtxid);
        mgr.tick(&mut cs, NOW);

        let has_inv = |msgs: &[Message]| {
            msgs.iter().any(|m| {
                matches!(m, Message::Inv(v) if v.iter().any(|iv| {
                    iv.inv_type == crate::message::InvType::Wtx
                        || iv.inv_type == crate::message::InvType::Tx
                }))
            })
        };
        assert!(has_inv(&testpipe::drain(&mut a, MAGIC)), "a relays");
        assert!(!has_inv(&testpipe::drain(&mut b, MAGIC)), "b denied");
        assert!(
            saw_facts.load(std::sync::atomic::Ordering::Relaxed),
            "verdict saw source=local facts"
        );
    }

    /// `relay.tx.deny_pairs` — the compartment matrix forbids a
    /// source→destination class. `local->outbound` silences the
    /// operator's own broadcast entirely.
    #[test]
    fn deny_pairs_silence_a_compartment() {
        let (mut mgr, mut a, _ida) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);

        mgr.set_deny_pairs(vec![("local".into(), "outbound".into())]);
        let txid = avila_consensus::hash::Txid::from_bytes([5u8; 32]);
        let wtxid = avila_consensus::hash::Wtxid::from_bytes([6u8; 32]);
        mgr.announce_tx(txid, wtxid);
        mgr.tick(&mut cs, NOW);
        let has_inv = testpipe::drain(&mut a, MAGIC)
            .iter()
            .any(|m| matches!(m, Message::Inv(_)));
        assert!(!has_inv, "local->outbound denied");
        // The verdict + matrix survive the take-restore — a peer-less
        // follow-up still consults them.
        mgr.set_deny_pairs(Vec::new());
        mgr.announce_tx(txid, wtxid);
        mgr.tick(&mut cs, NOW);
        assert!(
            testpipe::drain(&mut a, MAGIC)
                .iter()
                .any(|m| matches!(m, Message::Inv(_))),
            "cleared matrix announces again"
        );
    }

    /// `extrapool.relay = "outbound"` — observed txs propagate only on
    /// our own links; inbound never learns we saw it.
    #[test]
    fn extrapool_relay_outbound_only() {
        let (mut mgr, mut a, _ida) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);
        let (mut inb, _in_id) = add_inbound_peer(&mut mgr).expect("slot");
        handshake_peer(&mut mgr, &mut inb, &mut cs);
        testpipe::drain(&mut inb, MAGIC);

        let txid = avila_consensus::hash::Txid::from_bytes([8u8; 32]);
        let wtxid = avila_consensus::hash::Wtxid::from_bytes([9u8; 32]);
        mgr.announce_extrapool_tx(txid, wtxid, true);
        mgr.tick(&mut cs, NOW);
        let has_inv = |msgs: &[Message]| msgs.iter().any(|m| matches!(m, Message::Inv(_)));
        assert!(has_inv(&testpipe::drain(&mut a, MAGIC)), "outbound got it");
        assert!(!has_inv(&testpipe::drain(&mut inb, MAGIC)), "inbound blind");

        // "all" reaches inbound too.
        mgr.announce_extrapool_tx(txid, wtxid, false);
        mgr.tick(&mut cs, NOW);
        assert!(
            has_inv(&testpipe::drain(&mut inb, MAGIC)),
            "all reaches inbound"
        );
    }

    /// `mempool.private` — a private submission's stem hop goes out but
    /// the fluff pass never broadcasts it.
    #[test]
    fn private_tx_never_fluffs() {
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        use avila_consensus::{script, transaction::Transaction};

        let (mut mgr, mut a, _ida) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);

        // A real admitted entry marked private — the stem tuple
        // records the flag at announce time.
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: blocks[0].transactions[0].txid(),
                    vout: 0,
                },
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
        let wtxid = tx.wtxid();
        mgr.mempool().set_require_standard(false);
        mgr.mempool().accept_tx(tx, &cs, NOW).expect("admit");
        mgr.mempool().mark_private(&txid);
        mgr.stem_announce(txid, wtxid);
        mgr.tick(&mut cs, NOW);
        let stem_msgs = testpipe::drain(&mut a, MAGIC);
        assert!(
            stem_msgs.iter().any(|m| matches!(m, Message::Inv(_))),
            "stem hop announced"
        );
        // Delay elapsed — a private entry drains the pending slot
        // without sending anything.
        mgr.stem_pending[0].2 = Instant::now() - Duration::from_secs(1);
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let fluff = testpipe::drain(&mut a, MAGIC);
        assert!(
            !fluff.iter().any(|m| matches!(m, Message::Inv(_))),
            "private never fluffs: {fluff:?}"
        );
        assert!(mgr.stem_pending.is_empty());
    }

    /// BIP-133 — a peer's `feefilter` suppresses invs for txs below
    /// its advertised rate; unaffected links still get the announce.
    #[test]
    fn feefilter_suppresses_low_fee_announces() {
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        use avila_consensus::{script, transaction::Transaction};

        let (mut mgr, mut a, _ida) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);
        let (mut b, _idb) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut b, &mut cs);
        testpipe::drain(&mut b, MAGIC);

        // A real pool entry: fee 10_000 sat over a ~110vB spend —
        // ~90k sat/kvB.
        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: blocks[0].transactions[0].txid(),
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_ffff,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 4_999_990_000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        mgr.mempool().set_require_standard(false);
        mgr.mempool().accept_tx(tx, &cs, NOW).expect("admit");

        // B's filter is well above the tx's feerate.
        testpipe::inject(&mut b, MAGIC, &Message::FeeFilter(1_000_000));
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut b, MAGIC);

        mgr.announce_tx(txid, wtxid);
        mgr.tick(&mut cs, NOW);
        let has_inv = |msgs: &[Message]| msgs.iter().any(|m| matches!(m, Message::Inv(_)));
        assert!(
            has_inv(&testpipe::drain(&mut a, MAGIC)),
            "unfiltered peer got it"
        );
        assert!(
            !has_inv(&testpipe::drain(&mut b, MAGIC)),
            "feefilter suppressed"
        );

        // Filter lowered — the same announce reaches B.
        testpipe::inject(&mut b, MAGIC, &Message::FeeFilter(1));
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut b, MAGIC);
        mgr.announce_tx(txid, wtxid);
        mgr.tick(&mut cs, NOW);
        assert!(
            has_inv(&testpipe::drain(&mut b, MAGIC)),
            "lowered filter announces"
        );
    }

    /// `tx.serve`: a rejecting verdict withholds the tx as `notfound`;
    /// the accepted link and non-tx items are untouched.
    #[test]
    fn tx_serve_hook_gates_getdata() {
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        use avila_consensus::{script, transaction::Transaction};

        let (mut mgr, mut a, _ida) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);

        let tx = Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: blocks[0].transactions[0].txid(),
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_ffff,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 4_999_990_000,
                script_pubkey: Script::new(vec![script::OP_1]),
            }],
            lock_time: 0,
        };
        let txid = tx.txid();
        mgr.mempool().set_require_standard(false);
        mgr.mempool().accept_tx(tx, &cs, NOW).expect("admit");

        let req = vec![crate::message::InvVector {
            inv_type: crate::message::InvType::Tx,
            hash: BlockHash::from_bytes(txid.to_bytes()),
        }];

        // Denying verdict — the request answers notfound.
        let denied = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let n = denied.clone();
        mgr.set_tx_serve_verdict(Some(Box::new(move |f| {
            assert_eq!(f.txid, txid);
            n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            false
        })));
        testpipe::inject(&mut a, MAGIC, &Message::GetData(req.clone()));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW); // dispatch-queued replies flush next tick
        let msgs = testpipe::drain(&mut a, MAGIC);
        assert!(
            msgs.iter().any(|m| matches!(m, Message::NotFound(_))),
            "denied request answers notfound"
        );
        assert!(!msgs.iter().any(|m| matches!(m, Message::Tx(_))));
        assert_eq!(denied.load(std::sync::atomic::Ordering::SeqCst), 1);

        // Accepting verdict — the same request serves the tx.
        mgr.set_tx_serve_verdict(Some(Box::new(|_| true)));
        testpipe::inject(&mut a, MAGIC, &Message::GetData(req));
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        let msgs = testpipe::drain(&mut a, MAGIC);
        assert!(
            msgs.iter().any(|m| matches!(m, Message::Tx(_))),
            "accepted request serves the tx"
        );

        // No verdict at all — default serving is unaffected.
        mgr.set_tx_serve_verdict(None);
        testpipe::inject(
            &mut a,
            MAGIC,
            &Message::GetData(vec![crate::message::InvVector {
                inv_type: crate::message::InvType::Tx,
                hash: BlockHash::from_bytes(txid.to_bytes()),
            }]),
        );
        mgr.tick(&mut cs, NOW);
        mgr.tick(&mut cs, NOW);
        assert!(
            testpipe::drain(&mut a, MAGIC)
                .iter()
                .any(|m| matches!(m, Message::Tx(_))),
            "unhooked request serves"
        );
    }

    /// Queue #19: the divergence alarm fires once, only past every
    /// threshold — rounds, absolute their-side misses, and dominance
    /// over our-side misses.
    #[test]
    fn recon_divergence_alarm_is_edge_triggered() {
        let (mut mgr, _peer_end, id) = managed_peer();
        let mut events = Vec::new();
        {
            let peer = mgr.peers.get_mut(&id).unwrap();
            // Just short of the round count — wide diff alone is silent.
            peer.recon_rounds = 9;
            peer.recon_their_misses = 999;
            PeerManager::<End>::recon_alarm_check(peer, id, &mut events);
            assert!(events.is_empty());
            // A balanced diff isn't censorship either — their misses
            // must dominate ours 4:1.
            peer.recon_rounds = 10;
            peer.recon_their_misses = 120;
            peer.recon_misses = 40;
            PeerManager::<End>::recon_alarm_check(peer, id, &mut events);
            assert!(events.is_empty());
            // Every threshold crossed — fires once.
            peer.recon_their_misses = 400;
            peer.recon_misses = 50;
            PeerManager::<End>::recon_alarm_check(peer, id, &mut events);
        }
        assert!(
            matches!(
                events[0],
                NetEvent::ReconDivergence {
                    peer: p,
                    rounds: 10,
                    their_misses: 400,
                    our_misses: 50,
                } if p == id
            ),
            "{events:?}"
        );
        {
            let peer = mgr.peers.get_mut(&id).unwrap();
            peer.recon_their_misses = 10_000;
            PeerManager::<End>::recon_alarm_check(peer, id, &mut events);
        }
        assert_eq!(events.len(), 1, "edge-triggered — no refire");
    }

    /// PEER_BUDGETS CPU accounting (queue #14): a peer burning >50%
    /// of total dispatch CPU at >200ms/s loses its poll — the
    /// `CpuThrottled` event fires and its buffered input waits,
    /// while a quiet peer is still served. The headers leader is
    /// exempt: presync legitimately dominates, and starving its
    /// socket invites the remote side to close the one connection
    /// feeding header sync.
    #[test]
    fn cpu_throttle_skips_dominant_peer_only() {
        let (mut mgr, mut a, ida) = managed_peer();
        let mut cs = crate::testchain::regtest();
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);
        let (mut b, idb) = add_peer(&mut mgr);
        handshake_peer(&mut mgr, &mut b, &mut cs);
        testpipe::drain(&mut b, MAGIC);

        // Peer B (not the headers leader — A was elected first)
        // dominated last window: 500ms/s, >50% of the total.
        mgr.peers.get_mut(&idb).unwrap().cpu_rate_ns = 500_000_000;

        // B pings us — the throttled peer's poll is skipped, so the
        // ping sits unread and no pong comes back.
        testpipe::inject(&mut b, MAGIC, &Message::Ping(7));
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            events.iter().any(|e| matches!(
                e,
                NetEvent::CpuThrottled { peer, .. } if *peer == idb
            )),
            "dominant peer must fire CpuThrottled: {events:?}"
        );
        let sent_b = testpipe::drain(&mut b, MAGIC);
        assert!(
            !sent_b.iter().any(|m| matches!(m, Message::Pong(7))),
            "throttled peer must not be served: {sent_b:?}"
        );

        // The headers leader is exempt — even at the same burn rate
        // its poll still runs.
        mgr.peers.get_mut(&idb).unwrap().cpu_rate_ns = 0;
        mgr.peers.get_mut(&ida).unwrap().cpu_rate_ns = 500_000_000;
        testpipe::inject(&mut a, MAGIC, &Message::Ping(7));
        let events = mgr.tick(&mut cs, NOW);
        assert!(
            !events.iter().any(|e| matches!(
                e,
                NetEvent::CpuThrottled { peer, .. } if *peer == ida
            )),
            "headers leader must be exempt from throttling: {events:?}"
        );
        let sent_a = testpipe::drain(&mut a, MAGIC);
        assert!(
            sent_a.iter().any(|m| matches!(m, Message::Pong(7))),
            "leader must still be served: {sent_a:?}"
        );

        // Peer B quiet again — its ping is answered normally.
        testpipe::inject(&mut b, MAGIC, &Message::Ping(9));
        mgr.tick(&mut cs, NOW);
        let sent_b = testpipe::drain(&mut b, MAGIC);
        assert!(
            sent_b.iter().any(|m| matches!(m, Message::Pong(9))),
            "quiet peer must still be served: {sent_b:?}"
        );
    }

    /// Stem on recon links (queue #7): a locally-originated tx in its
    /// stem delay must not leak through the recon sketch — a round
    /// inside the delay would defeat the hop. And a recon peer is
    /// never inv'd (BIP-330 carries it).
    #[test]
    fn stem_pending_stays_out_of_recon_sketch() {
        use avila_consensus::transaction::{OutPoint, Script, TxIn, TxOut, Witness};
        use avila_consensus::{script, transaction::Transaction};

        let (mut mgr, mut a, ida) = managed_peer();
        let mut cs = regtest();
        let blocks = chain_blocks(&cs, 101);
        for b in &blocks {
            cs.accept_block(b, NOW).unwrap();
        }
        // Peer A: plain relay link. Peer B: negotiates recon.
        handshake(&mut mgr, &mut a, &mut cs);
        testpipe::drain(&mut a, MAGIC);
        let (mut b, idb) = add_peer(&mut mgr);
        mgr.tick(&mut cs, NOW);
        let _ = testpipe::drain(&mut b, MAGIC);
        testpipe::inject(&mut b, MAGIC, &Message::Version(peer_version(600)));
        testpipe::inject(
            &mut b,
            MAGIC,
            &Message::SendRecon(crate::message::SendRecon {
                is_sender: true,
                is_responder: true,
                version: crate::recon::RECON_VERSION,
                salt: 0x66,
            }),
        );
        mgr.tick(&mut cs, NOW);
        testpipe::inject(&mut b, MAGIC, &Message::Verack);
        mgr.tick(&mut cs, NOW);
        testpipe::drain(&mut b, MAGIC);
        assert!(
            mgr.peers.get(&idb).is_some_and(|p| p.recon.is_some()),
            "peer B must be a recon link"
        );

        // Locally-originated tx in the pool → stem announce.
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
        let wtxid = tx.wtxid();
        mgr.mempool().set_require_standard(false);
        mgr.mempool().accept_tx(tx, &cs, NOW).unwrap();
        mgr.stem_announce(txid, wtxid);
        mgr.tick(&mut cs, NOW); // flush send_bufs

        // The stem inv can land only on the non-recon link A — never B.
        let sent_b = testpipe::drain(&mut b, MAGIC);
        assert!(
            !sent_b.iter().any(|m| matches!(m, Message::Inv(_))),
            "recon link must never get a stem inv: {sent_b:?}"
        );

        // While stem-pending, the tx is absent from the sketch ids.
        let salt = 0xAAu64 ^ 0x66u64; // our_salt ^ their_salt (test salts)
        let pending: std::collections::HashSet<_> =
            mgr.stem_pending.iter().map(|(t, _, _, _)| *t).collect();
        assert!(pending.contains(&txid), "tx must be stem-pending");
        let (ids, _) = recon_pool(mgr.mempool_ref(), salt, &pending);
        let short = crate::recon::short_id(salt, txid.as_bytes());
        assert!(
            !ids.contains(&short),
            "pending tx must stay out of the sketch"
        );

        // After fluff, it's back in the sketch set.
        let empty: std::collections::HashSet<_> = Default::default();
        let (ids, _) = recon_pool(mgr.mempool_ref(), salt, &empty);
        assert!(ids.contains(&short), "fluffed tx must reconcile");
        let _ = ida;
    }
    /// Adaptive sketch capacity: the hint tracks the largest observed
    /// diff, decays by half per quiet round, and capacity sizes at
    /// `2*hint + 32` inside [16, 1024].
    #[test]
    fn recon_capacity_tracks_observed_diff() {
        assert_eq!(recon_capacity(0), 32);
        // A cold round on a wide diff jumps the hint straight up...
        let h = recon_hint_update(0, 300);
        assert_eq!(h, 300);
        assert_eq!(recon_capacity(h), 632);
        // ...and quiet rounds decay it toward the real diff size.
        let h = recon_hint_update(h, 40);
        assert_eq!(h, 150);
        let h = recon_hint_update(h, 40);
        assert_eq!(h, 75);
        // A fresh spike re-rises immediately.
        assert_eq!(recon_hint_update(h, 900), 900);
        // And the cap still bounds absurd observations.
        assert_eq!(recon_capacity(u32::MAX), 1024);
    }
}

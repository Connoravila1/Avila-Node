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
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::BlockHash;

use crate::addrman::{self, AddrBook};
use crate::message::{AddrV2Entry, Message, NetAddr};
use crate::session::{PeerInfo, PeerSession, SessionError, SessionEvent, build_version};
use crate::sync::{MAX_BLOCKS_IN_TRANSIT_PER_PEER, PeerSync};

/// Maximum simultaneous peers — small by design; more arrive when
/// connection scheduling matures.
pub const DEFAULT_MAX_PEERS: usize = 8;

/// Global bound on outstanding block reservations across the whole peer
/// set — independent of peer count, so aggregate download memory stays
/// predictable (Core bounds this through `BLOCK_DOWNLOAD_WINDOW`).
pub const MAX_BLOCKS_IN_TRANSIT_TOTAL: usize = 1024;

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
    /// Gossiped peer addresses — discovery lives here.
    addrbook: AddrBook,
}

impl<S: Read + Write> PeerManager<S> {
    /// An empty manager — `max_peers` bounds the set.
    #[must_use]
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            next_id: 0,
            max_peers,
            headers_leader: None,
            max_in_flight_total: MAX_BLOCKS_IN_TRANSIT_TOTAL,
            addrbook: AddrBook::new(),
        }
    }

    /// Live peer count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
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
        if !self.has_slot() {
            self.evict_worst_inbound();
        }
        self.add(session, None, true)
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
            self.peers.remove(&id);
        }
        worst
    }

    fn add(
        &mut self,
        session: PeerSession<S>,
        remote: Option<NetAddr>,
        inbound: bool,
    ) -> Option<u64> {
        if !self.has_slot() {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
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
        let Self {
            peers,
            addrbook,
            headers_leader,
            ..
        } = self;
        let mut announce_tip: Option<u64> = None;
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
                            &mut global_free,
                            &mut events,
                            &mut dead,
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
                }
            }
            // Stall eviction.
            if peer.sync.stalled() {
                dead.push((id, DisconnectReason::Stalled));
            }
        }
        for (id, reason) in dead {
            self.peers.remove(&id);
            if self.headers_leader == Some(id) {
                self.headers_leader = None;
            }
            events.push(NetEvent::Disconnected { peer: id, reason });
        }
        // Announce a newly connected tip to every established peer except
        // the one that delivered it (Core's `NewPoWValidBlock` relay).
        if let Some(source) = announce_tip {
            // The connected tip — not `tree().tip()`, which is the best
            // *header* and may sit above the connected chain.
            let tip_hash = cs.chain().last().copied();
            let tip_header = tip_hash.and_then(|h| cs.tree().get(&h)).map(|n| n.header);
            for (&id, peer) in &mut self.peers {
                if id == source || !peer.session.established() {
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
        self.fill_queues(cs);
        events
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
        for peer in self.peers.values_mut() {
            if !peer.session.established()
                || peer.sync.stalled()
                || peer.sync.in_flight() >= MAX_BLOCKS_IN_TRANSIT_PER_PEER
            {
                reserved.extend(peer.sync.reserved_hashes().copied());
                continue;
            }
            if reserved.len() >= self.max_in_flight_total {
                break;
            }
            let unfetched: Vec<BlockHash> = cs
                .tree()
                .headers_by_height()
                .iter()
                .map(|h| h.hash())
                .filter(|h| !cs.have_body(h) && !reserved.contains(h))
                .take(
                    crate::sync::MAX_BLOCKS_IN_TRANSIT_PER_PEER
                        .min(self.max_in_flight_total - reserved.len()),
                )
                .collect();
            if unfetched.is_empty() {
                break;
            }
            if let Some(req) = peer.sync.want_blocks_excluding(cs, &unfetched, &reserved) {
                let _ = peer.session.send(&req);
            }
            reserved.extend(peer.sync.reserved_hashes().copied());
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
        global_free: &mut usize,
        events: &mut Vec<NetEvent>,
        dead: &mut Vec<(u64, DisconnectReason)>,
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
                });
                events.push(NetEvent::Connected {
                    peer: id,
                    info: Box::new(info),
                });
                let req = peer.sync.request_headers(cs);
                let _ = peer.session.send(&req);
            }
            SessionEvent::Message(Message::Headers(headers)) => {
                match peer.sync.on_headers(cs, &headers, now) {
                    Ok(outcome) => {
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
                if let Some(req) = peer.sync.on_inv(cs, &invs, *global_free) {
                    *global_free = global_free.saturating_sub(peer.sync.in_flight() - before);
                    let _ = peer.session.send(&req);
                }
            }
            SessionEvent::Message(Message::Block(block)) => {
                match peer.sync.on_block(cs, &block, now) {
                    Ok(outcome) => {
                        peer.last_useful = Instant::now();
                        if let avila_consensus::chainstate::Acceptance::Connected { .. } =
                            outcome.acceptance
                        {
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
            SessionEvent::Message(Message::GetHeaders(req)) => {
                let reply = PeerSync::serve_getheaders(cs, &req);
                let _ = peer.session.send(&reply);
            }
            SessionEvent::Message(Message::GetData(reqs)) => {
                for reply in PeerSync::serve_getdata(cs, &reqs) {
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
            SessionEvent::Message(Message::GetAddr) => {
                let entries = addrbook
                    .sample()
                    .iter()
                    .map(|a| addr_v2_of(a, now))
                    .collect();
                let _ = peer.session.send(&Message::AddrV2(entries));
            }
            SessionEvent::Message(Message::Addr(entries)) => {
                addrbook.add_many(entries.iter().map(|e| (e.addr, e.time)), now);
            }
            SessionEvent::Message(Message::AddrV2(entries)) => {
                addrbook.add_many(
                    entries
                        .iter()
                        .filter_map(|e| net_addr_of_v2(e).map(|a| (a, e.time))),
                    now,
                );
            }
            SessionEvent::Message(_) => {}
        }
    }

    /// Total in-flight block requests across all peers.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.peers.values().map(|p| p.sync.in_flight()).sum()
    }

    /// The peers' ids (for scheduling decisions above this layer).
    #[must_use]
    pub fn peer_ids(&self) -> Vec<u64> {
        self.peers.keys().copied().collect()
    }

    /// Forcibly removes a peer (caller-initiated disconnect).
    pub fn disconnect(&mut self, id: u64) {
        self.peers.remove(&id);
    }
}

impl PeerManager<TcpStream> {
    /// Connects to `addr` over TCP and registers the outbound session.
    /// Nonblocking — `tick` does the polling.
    pub fn connect(
        &mut self,
        addr: SocketAddr,
        magic: [u8; 4],
        our_version: u64, // nonce for build_version
        start_height: i32,
    ) -> Result<Option<u64>, SessionError> {
        let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        stream.set_nonblocking(true)?;
        stream.set_nodelay(true)?;
        let version = build_version(
            our_version,
            start_height,
            crate::addrman::net_addr_of(addr, 0),
        );
        let session = PeerSession::initiate(stream, magic, version, SEND_BUDGET_PER_PEER)?;
        Ok(self.add(session, Some(crate::addrman::net_addr_of(addr, 0)), false))
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
        if events
            .iter()
            .any(|e| matches!(e, NetEvent::Disconnected { .. }))
        {
            self.maintain_outbounds(magic, start_height);
        }
        events
    }

    /// Dials address-book candidates until the peer set is full or the
    /// book runs dry — the caller runs this between `tick`s to keep
    /// outbound connectivity up. Returns the endpoints attempted.
    pub fn maintain_outbounds(&mut self, magic: [u8; 4], start_height: i32) -> Vec<SocketAddr> {
        let mut dialed = Vec::new();
        while self.has_slot()
            && let Some(candidate) = self.addrbook.select()
        {
            let sock = addrman::socket_addr(&candidate);
            self.addrbook.mark_attempt(&candidate);
            dialed.push(sock);
            match self.connect(sock, magic, sock.port() as u64, start_height) {
                Ok(Some(_)) => {}
                Ok(None) => break,  // raced to full
                Err(_) => continue, // unreachable — try the next candidate
            }
        }
        dialed
    }
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
            build_version(1, 0, NetAddr::unspecified()),
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
                build_version(1, 0, NetAddr::unspecified()),
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
                    build_version(2, 0, NetAddr::unspecified()),
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
            build_version(9, 0, NetAddr::unspecified()),
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
            build_version(9, 0, NetAddr::unspecified()),
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
            build_version(9, 0, NetAddr::unspecified()),
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
    fn addr_gossip_fills_the_book() {
        let (mut mgr, mut peer, _id) = managed_peer();
        let mut cs = regtest();
        handshake(&mut mgr, &mut peer, &mut cs);
        testpipe::drain(&mut peer, MAGIC);

        let gossip = vec![
            AddrEntry {
                time: NOW - 10,
                addr: addrman::loopback(18444, NODE_NETWORK),
            },
            AddrEntry {
                time: NOW - 5,
                addr: addrman::loopback(18445, NODE_NETWORK),
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
            addr: addrman::loopback(18444, NODE_NETWORK),
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
}

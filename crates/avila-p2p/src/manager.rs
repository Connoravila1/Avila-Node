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

use crate::message::{Message, NetAddr};
use crate::session::{PeerInfo, PeerSession, SessionError, SessionEvent, build_version};
use crate::sync::PeerSync;

/// Maximum simultaneous peers — small by design; more arrive when
/// connection scheduling matures.
pub const DEFAULT_MAX_PEERS: usize = 8;

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
    /// Time of the last received message of any kind.
    last_rx: Instant,
    /// Outstanding handshake deadline check cadence.
    last_ping: Instant,
    /// Blocks we've asked this peer for, awaiting bodies.
    sent_requests: usize,
}

/// A bounded set of peers sharing one [`Chainstate`].
pub struct PeerManager<S> {
    peers: HashMap<u64, PeerEntry<S>>,
    next_id: u64,
    max_peers: usize,
}

impl<S: Read + Write> PeerManager<S> {
    /// An empty manager — `max_peers` bounds the set.
    #[must_use]
    pub fn new(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            next_id: 0,
            max_peers,
        }
    }

    /// Live peer count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether no peers are connected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Whether another outbound peer may be added.
    #[must_use]
    pub fn has_slot(&self) -> bool {
        self.peers.len() < self.max_peers
    }

    /// Registers an outbound session (already constructed, version queued).
    /// Returns the peer id, or `None` if the peer set is full.
    pub fn add_outbound(&mut self, session: PeerSession<S>) -> Option<u64> {
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
                last_rx: now,
                last_ping: now,
                sent_requests: 0,
            },
        );
        Some(id)
    }

    /// Registers an inbound session. Subject to the same peer cap.
    pub fn add_inbound(&mut self, session: PeerSession<S>) -> Option<u64> {
        self.add_outbound(session)
    }

    /// Drives every session once: flush → read → dispatch → reply. Returns
    /// the events a caller should observe; `cs` absorbs headers/blocks.
    pub fn tick(&mut self, cs: &mut Chainstate, now: u32) -> Vec<NetEvent> {
        let mut events = Vec::new();
        let mut dead = Vec::new();
        for (&id, peer) in &mut self.peers {
            if let Err(e) = peer.session.check_handshake_timeout() {
                dead.push((id, DisconnectReason::Session(e.to_string())));
                continue;
            }
            match peer.session.poll() {
                Ok(peer_events) => {
                    for event in peer_events {
                        peer.last_rx = Instant::now();
                        Self::dispatch(id, peer, event, cs, now, &mut events, &mut dead);
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
            events.push(NetEvent::Disconnected { peer: id, reason });
        }
        events
    }

    /// One peer's event → replies and chainstate effects.
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        id: u64,
        peer: &mut PeerEntry<S>,
        event: SessionEvent,
        cs: &mut Chainstate,
        now: u32,
        events: &mut Vec<NetEvent>,
        dead: &mut Vec<(u64, DisconnectReason)>,
    ) {
        match event {
            SessionEvent::Established => {
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
                            let _ = peer.session.send(&next);
                        }
                        if !outcome.fetchable.is_empty()
                            && let Some(req) = peer.sync.want_blocks(cs, &outcome.fetchable)
                        {
                            peer.sent_requests += 1;
                            let _ = peer.session.send(&req);
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
                if let Some(req) = peer.sync.on_inv(cs, &invs) {
                    let _ = peer.session.send(&req);
                }
            }
            SessionEvent::Message(Message::Block(block)) => {
                match peer.sync.on_block(cs, &block, now) {
                    Ok(outcome) => {
                        if outcome.was_in_flight {
                            peer.sent_requests = peer.sent_requests.saturating_sub(1);
                        }
                        if let avila_consensus::chainstate::Acceptance::Connected { .. } =
                            outcome.acceptance
                        {
                            events.push(NetEvent::TipAdvanced(cs.chain().len() as u32 - 1));
                        }
                        // Freed a slot — ask for more if indexed blocks are
                        // still unfetched.
                        let want: Vec<BlockHash> = cs
                            .tree()
                            .headers_by_height()
                            .iter()
                            .map(|h| h.hash())
                            .filter(|h| !cs.have_body(h))
                            .take(64)
                            .collect();
                        if let Some(req) = peer.sync.want_blocks(cs, &want) {
                            let _ = peer.session.send(&req);
                        }
                    }
                    Err(e) => dead.push((id, DisconnectReason::Misbehavior(e.to_string()))),
                }
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
            // getaddr: we have no address book yet — answer with nothing.
            SessionEvent::Message(Message::GetAddr) => {
                let _ = peer.session.send(&Message::AddrV2(vec![]));
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
        let version = build_version(our_version, start_height, net_addr(addr));
        let session = PeerSession::initiate(stream, magic, version, SEND_BUDGET_PER_PEER)?;
        Ok(self.add_outbound(session))
    }
}

/// `NetAddr` for a socket endpoint (v4-mapped when needed).
fn net_addr(sock: SocketAddr) -> NetAddr {
    NetAddr {
        services: 0,
        ip: match sock.ip() {
            std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            std::net::IpAddr::V6(v6) => v6.octets(),
        },
        port: sock.port(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::message::{GetHeaders, InvType, InvVector, NODE_NETWORK, PROTOCOL_VERSION, Version};
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
        let (mgr, _peer, _id) = managed_peer();
        let (us2, _peer2) = testpipe::pair();
        let s2 = PeerSession::initiate(
            us2,
            MAGIC,
            build_version(2, 0, NetAddr::unspecified()),
            BUDGET,
        )
        .unwrap();
        let mut mgr2 = PeerManager::<End>::new(1);
        let _ = mgr2.add_outbound(s2);
        assert!(
            mgr2.add_outbound({
                let (us3, _p3) = testpipe::pair();
                PeerSession::initiate(
                    us3,
                    MAGIC,
                    build_version(3, 0, NetAddr::unspecified()),
                    BUDGET,
                )
                .unwrap()
            })
            .is_none()
        );
        assert_eq!(mgr2.len(), 1);
        drop(mgr);
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

        // A header that doesn't attach to anything we know.
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
}

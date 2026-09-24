//! One peer's protocol state: the `version`/`verack` handshake, liveness
//! (`ping`/`pong` answered at this layer), and the send/receive queues.
//!
//! The session is transport-agnostic — anything `Read + Write` works, which
//! is what lets tests drive peers over in-memory pipes. Socket selection,
//! real-clock scheduling, and multi-peer multiplexing live in the
//! connection layer above this.
//!
//! Handshake choreography mirrors Core v29's `net_processing.cpp`:
//!
//! * Outbound: we send `version` on connect (`PushNodeVersion`). On their
//!   `version` we reply `wtxidrelay`, `sendaddrv2`, `verack`; their
//!   `verack` completes the handshake.
//! * Inbound: on the peer's `version` we send `version`, `wtxidrelay`,
//!   `sendaddrv2`, `verack` in one burst; their `verack` completes it.
//! * Anything but `version` before the peer's `version` is ignored —
//!   Core logs "non-version message before version handshake" and drops
//!   the message without disconnecting.
//! * `wtxidrelay`/`sendaddrv2` after `verack` is a BIP339/BIP155
//!   violation and disconnects the peer.
//! * A second `version` disconnects the peer.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::codec::{Command, FrameDecoder, FrameError, encode_frame};
use crate::message::{
    Message, NODE_NETWORK, NODE_WITNESS, NetAddr, PROTOCOL_VERSION, PayloadError, Version,
};

/// Core's `HANDSHAKE_TIMEOUT` — a peer that never finishes the version
/// handshake is disconnected.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

/// Bytes read per socket call inside `poll`.
const READ_CHUNK: usize = 8 * 1024;

/// The services we advertise on every connection. `NODE_P2P_V2` is
/// deliberately absent — BIP324 isn't implemented yet, and advertising it
/// would make v29+ peers open an encrypted v2 stream we can't read.
pub const OUR_SERVICES: u64 = NODE_NETWORK | NODE_WITNESS;

/// Where the session is in the `version`/`verack` exchange.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Handshake {
    /// We have not yet received the peer's `version`.
    AwaitVersion,
    /// Peer's `version` arrived and our reply burst is queued; awaiting
    /// their `verack`.
    AwaitVerack,
    /// Both `verack`s exchanged.
    Done,
}

/// What the peer told us in its `version` plus its negotiation messages.
#[derive(Clone, Debug)]
pub struct PeerInfo {
    /// The peer's protocol version.
    pub version: i32,
    /// Services the peer offers.
    pub services: u64,
    /// The peer's claimed best height.
    pub start_height: i32,
    /// The peer's user agent.
    pub user_agent: String,
    /// Whether the peer wants to relay transactions to us.
    pub relay: bool,
    /// Whether the peer announced BIP339 wtxid relay.
    pub wtxid_relay: bool,
    /// Whether the peer understands BIP155 addrv2.
    pub addrv2: bool,
    /// The peer's BIP330 reconciliation negotiation, if it sent
    /// `sendrecon` during the handshake — `None` means the link runs
    /// ordinary inv/getdata tx relay only.
    pub recon: Option<crate::message::SendRecon>,
}

/// Wire telemetry for one session — what `getpeerinfo` reports. Bytes
/// are counted where they actually move: outbound at `send` (queue
/// time — a failed flush kills the session anyway), inbound at `poll`'s
/// read; per-command histograms use whole-frame sizes.
#[derive(Clone, Debug, Default)]
pub struct SessionTelemetry {
    /// Wire bytes sent to this peer.
    pub bytes_sent: u64,
    /// Wire bytes read from this peer.
    pub bytes_recv: u64,
    /// Outbound wire bytes by command name.
    pub sent_by_msg: std::collections::HashMap<String, u64>,
    /// Inbound wire bytes by command name (payload + 24-byte header).
    pub recv_by_msg: std::collections::HashMap<String, u64>,
    /// Wall-clock connection time (Core's `conntime`).
    pub connected: i64,
    /// Wall-clock of the last send (`lastsend`); 0 before any traffic.
    pub last_send: i64,
    /// Wall-clock of the last received frame (`lastrecv`); 0 likewise.
    pub last_recv: i64,
    /// Opaque per-session token (Core's `session_id`).
    pub session_id: u64,
}

/// Monotonic session tokens — nanos-seeded so ids differ across
/// process restarts, then a counter so same-instant sessions differ.
fn next_session_id() -> u64 {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering::Relaxed;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 | (d.as_secs() & 0xffff_ffff) << 32)
        .unwrap_or(0);
    nanos.rotate_left(7) ^ seq.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

/// Wall-clock UNIX seconds — the default session clock. Callers that
/// keep a mockable clock (Core's `GetTime`) substitute it via
/// [`PeerSession::set_clock`]; [`build_version`] takes the epoch as an
/// argument for the same reason.
#[must_use]
pub fn wall_epoch() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Something the session wants the caller to know. Interpreting `Message`
/// payloads (is this header valid? do we want these blocks?) is the sync
/// layer's job — the session only reports wire facts.
#[derive(Clone, Debug, PartialEq)]
pub enum SessionEvent {
    /// The handshake completed — data commands are now legal both ways.
    Established,
    /// A non-handshake message arrived.
    Message(Message),
}

/// Why the session is over — the peer's fault, an I/O failure, or a
/// timeout.
#[derive(Debug, Error)]
pub enum SessionError {
    /// The socket failed.
    #[error("io: {0}")]
    Io(#[from] io::Error),
    /// A frame violated the wire format (bad magic, checksum, size).
    #[error("wire: {0}")]
    Frame(#[from] FrameError),
    /// A known command's payload didn't decode.
    #[error("payload: {0}")]
    Payload(#[from] PayloadError),
    /// The peer sent a second `version`.
    #[error("duplicate version message")]
    DuplicateVersion,
    /// `wtxidrelay` or `sendaddrv2` arrived after `verack`.
    #[error("negotiation message after handshake completed")]
    LateNegotiation,
    /// The handshake didn't finish within [`HANDSHAKE_TIMEOUT`].
    #[error("handshake timeout")]
    HandshakeTimeout,
    /// The stream reached end-of-file — the peer hung up.
    #[error("peer closed the connection")]
    Eof,
    /// A BIP324 packet failed to authenticate or parse — the
    /// transport desynchronized and the connection is unusable.
    #[error("v2 transport: {0}")]
    Transport(&'static str),
    /// The peer answered the v2 handshake with a v1 `version` frame —
    /// redial with the cleartext transport (Core's
    /// `ShouldReconnectV1`).
    #[error("peer is v1-only — redial cleartext")]
    V1Fallback,
}

/// A single peer connection's protocol state.
pub struct PeerSession<S> {
    stream: S,
    magic: [u8; 4],
    decoder: FrameDecoder,
    send_buf: VecDeque<u8>,
    state: Handshake,
    our_version: Version,
    /// The salt we advertised in `sendrecon` — derived from the session
    /// id + our version nonce so each link's short-ids differ.
    recon_salt: u64,
    /// Whether we initiated the connection (Core's outbound vs inbound).
    outbound: bool,
    peer: Option<PeerInfo>,
    connected_at: Instant,
    /// Wire counters and wall-clock times for `getpeerinfo`.
    telemetry: SessionTelemetry,
    /// Maximum bytes allowed outstanding in `send_buf`.
    send_budget: usize,
    /// The clock `conntime`/`lastsend`/`lastrecv` read — [`wall_epoch`]
    /// until the owning manager substitutes its own.
    clock: fn() -> i64,
    /// BIP324 channel state when this session speaks v2; `None` for
    /// the legacy cleartext wire.
    v2: Option<crate::bip324::V2Channel>,
}

impl<S: Read + Write> PeerSession<S> {
    /// Wraps `stream` for an outbound connection — our `version` is queued
    /// immediately, matching `PushNodeVersion` on connect.
    ///
    /// # Errors
    /// [`SessionError`] if queueing the initial `version` overflows
    /// `send_budget` (i.e. the budget is smaller than one frame).
    pub fn initiate(
        stream: S,
        magic: [u8; 4],
        our_version: Version,
        send_budget: usize,
    ) -> Result<Self, SessionError> {
        let mut session = Self::new(stream, magic, our_version, send_budget, true);
        session.send(&Message::Version(session.our_version.clone()))?;
        Ok(session)
    }

    /// `initiate` over BIP324: run the ellswift handshake on the
    /// (blocking) stream, send our garbage terminator + version
    /// packet, then queue `version` as the first encrypted message.
    ///
    /// # Errors
    /// [`SessionError::V1Fallback`] when the peer's first bytes were
    /// the v1 `magic||version` prefix — Core's `ShouldReconnectV1`;
    /// the caller should redial with [`Self::initiate`].
    pub fn initiate_v2(
        mut stream: S,
        magic: [u8; 4],
        our_version: Version,
        send_budget: usize,
    ) -> Result<Self, SessionError> {
        match crate::bip324::handshake(&mut stream, magic).map_err(SessionError::Io)? {
            crate::bip324::Handshake::V2(cipher, garbage) => {
                let mut channel = crate::bip324::V2Channel::new(cipher, garbage);
                let tail = channel.handshake_tail();
                stream.write_all(&tail).map_err(SessionError::Io)?;
                let mut session = Self::new(stream, magic, our_version, send_budget, true);
                session.v2 = Some(channel);
                session.send(&Message::Version(session.our_version.clone()))?;
                Ok(session)
            }
            crate::bip324::Handshake::V1Fallback => Err(SessionError::V1Fallback),
        }
    }

    /// `initiate` on a stream whose BIP324 handshake already ran —
    /// for callers that interleave `start_handshake`/`finish_handshake`
    /// themselves (in-memory pipes, future inbound accepts).
    ///
    /// # Errors
    /// Same budget overflow as [`Self::initiate`].
    pub fn initiate_v2_channel(
        stream: S,
        magic: [u8; 4],
        our_version: Version,
        send_budget: usize,
        channel: crate::bip324::V2Channel,
    ) -> Result<Self, SessionError> {
        let mut session = Self::new(stream, magic, our_version, send_budget, true);
        session.v2 = Some(channel);
        session.send(&Message::Version(session.our_version.clone()))?;
        Ok(session)
    }

    /// `accept` on a responder-side BIP324 channel — the inbound
    /// half of `initiate_v2_channel`.
    #[must_use]
    pub fn accept_v2_channel(
        stream: S,
        magic: [u8; 4],
        our_version: Version,
        send_budget: usize,
        channel: crate::bip324::V2Channel,
    ) -> Self {
        let mut session = Self::new(stream, magic, our_version, send_budget, false);
        session.v2 = Some(channel);
        session
    }

    /// Wraps `stream` for an inbound connection — we wait for the peer's
    /// `version` before saying anything.
    #[must_use]
    pub fn accept(stream: S, magic: [u8; 4], our_version: Version, send_budget: usize) -> Self {
        Self::new(stream, magic, our_version, send_budget, false)
    }

    fn new(
        stream: S,
        magic: [u8; 4],
        our_version: Version,
        send_budget: usize,
        outbound: bool,
    ) -> Self {
        let session_id = next_session_id();
        let recon_salt = session_id ^ our_version.nonce;
        Self {
            stream,
            magic,
            decoder: FrameDecoder::new(magic),
            send_buf: VecDeque::new(),
            state: Handshake::AwaitVersion,
            our_version,
            outbound,
            peer: None,
            connected_at: Instant::now(),
            telemetry: SessionTelemetry {
                connected: wall_epoch(),
                session_id,
                ..SessionTelemetry::default()
            },
            send_budget,
            clock: wall_epoch,
            v2: None,
            recon_salt,
        }
    }

    /// The salt this session advertised in `sendrecon` — the manager
    /// combines it with the peer's to key link short-ids.
    #[must_use]
    pub fn recon_salt(&self) -> u64 {
        self.recon_salt
    }

    /// Swaps the telemetry clock — the manager calls this at
    /// registration so `conntime`/`lastsend`/`lastrecv` live on the
    /// node's (possibly mocked) clock, like Core's `GetTime` reads.
    /// `connected` re-stamps to registration time; any pre-registration
    /// traffic stamps re-anchor to the same domain.
    pub fn set_clock(&mut self, clock: fn() -> i64) {
        self.clock = clock;
        let now = clock();
        self.telemetry.connected = now;
        if self.telemetry.last_send > 0 {
            self.telemetry.last_send = now;
        }
        if self.telemetry.last_recv > 0 {
            self.telemetry.last_recv = now;
        }
    }

    /// The peer's `version` fields once received.
    #[must_use]
    pub fn peer(&self) -> Option<&PeerInfo> {
        self.peer.as_ref()
    }

    /// The nonce we advertised in our own `version` (Core's
    /// `CNode::GetLocalNonce`). On an outbound dial the manager remembers
    /// this so a matching nonce on a later *inbound* connection's
    /// `version` can be recognized as our own loopback — Core's
    /// `CheckIncomingNonce` self-connection check.
    #[must_use]
    pub fn our_nonce(&self) -> u64 {
        self.our_version.nonce
    }

    /// Whether the handshake has completed.
    #[must_use]
    pub fn established(&self) -> bool {
        self.state == Handshake::Done
    }

    /// Whether `flush` has bytes left to write.
    #[must_use]
    pub fn wants_write(&self) -> bool {
        !self.send_buf.is_empty()
    }

    /// Bytes queued for the peer right now.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.send_buf.len()
    }

    /// Wire counters and timestamps — the `getpeerinfo` telemetry set.
    #[must_use]
    pub fn telemetry(&self) -> SessionTelemetry {
        self.telemetry.clone()
    }

    /// `getpeerinfo.transport_protocol_type` — "v2" when BIP324 is
    /// active (Core also reports "detecting" mid-handshake; our
    /// sessions resolve before registration).
    #[must_use]
    pub fn transport_protocol(&self) -> &'static str {
        if self.v2.is_some() { "v2" } else { "v1" }
    }

    /// `getpeerinfo.session_id` — the BIP324 session id, hex; empty
    /// on v1 like Core.
    #[must_use]
    pub fn v2_session_id(&self) -> Option<[u8; 32]> {
        self.v2.as_ref().map(|c| c.session_id())
    }

    /// The wrapped stream — callers flip socket options
    /// (nonblocking, timeouts) around the blocking handshake
    /// `initiate_v2` performs.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Fails the session if the handshake has run past [`HANDSHAKE_TIMEOUT`].
    ///
    /// # Errors
    /// [`SessionError::HandshakeTimeout`] once the deadline passes.
    pub fn check_handshake_timeout(&self) -> Result<(), SessionError> {
        if self.state != Handshake::Done && self.connected_at.elapsed() > HANDSHAKE_TIMEOUT {
            return Err(SessionError::HandshakeTimeout);
        }
        Ok(())
    }

    /// Queues a message for sending. Rather than buffering unboundedly,
    /// returns an error once `send_budget` bytes are outstanding — the
    /// caller stops generating traffic for this peer until `flush` drains
    /// the queue.
    ///
    /// # Errors
    /// [`SessionError::Io`] with `ErrorKind::WriteZero` on budget overflow.
    pub fn send(&mut self, message: &Message) -> Result<(), SessionError> {
        let command = message
            .command()
            .ok_or(SessionError::Frame(FrameError::BadCommand))?;
        let frame = match &mut self.v2 {
            // v2: one message = one packet — `msgtype || payload` is
            // the AEAD plaintext (no magic/length/checksum).
            Some(channel) => channel.encode_message(command.name(), &message.encode()),
            None => encode_frame(self.magic, command, &message.encode()),
        };
        if self.send_buf.len() + frame.len() > self.send_budget {
            return Err(SessionError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "per-peer send budget exhausted",
            )));
        }
        *self
            .telemetry
            .sent_by_msg
            .entry(command.name().to_string())
            .or_insert(0) += frame.len() as u64;
        self.telemetry.bytes_sent += frame.len() as u64;
        self.telemetry.last_send = (self.clock)();
        self.send_buf.extend(frame);
        Ok(())
    }

    /// Writes as much of `send_buf` as the socket accepts; `WouldBlock`
    /// leaves the remainder queued.
    ///
    /// # Errors
    /// Propagates real I/O failures.
    pub fn flush(&mut self) -> Result<(), SessionError> {
        while !self.send_buf.is_empty() {
            let n = match self.stream.write(self.send_buf.make_contiguous()) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break, // try again next poll
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(SessionError::Io(e)),
            };
            if n == 0 {
                return Err(SessionError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "zero-length socket write",
                )));
            }
            self.send_buf.drain(..n);
        }
        Ok(())
    }

    /// Flushes the send queue, then reads whatever is available and
    /// processes every complete frame. Nonblocking sockets return
    /// `Ok(vec![])` on `WouldBlock`.
    ///
    /// # Errors
    /// Any [`SessionError`] — all are terminal for the peer.
    pub fn poll(&mut self) -> Result<Vec<SessionEvent>, SessionError> {
        self.flush()?;
        let mut scratch = [0u8; READ_CHUNK];
        let mut events = Vec::new();
        loop {
            match self.stream.read(&mut scratch) {
                Ok(0) => return Err(SessionError::Eof),
                Ok(n) => {
                    self.telemetry.bytes_recv += n as u64;
                    match &mut self.v2 {
                        Some(channel) => {
                            // Packet layer yields complete
                            // (msgtype, payload) pairs — the decoder
                            // step is per-packet, not per-frame.
                            let msgs = channel
                                .feed(&scratch[..n])
                                .map_err(SessionError::Transport)?;
                            for (name, payload) in msgs {
                                let Some(command) = Command::new(&name) else {
                                    continue; // undecodable name — drop like Core
                                };
                                *self.telemetry.recv_by_msg.entry(name).or_insert(0) +=
                                    payload.len() as u64;
                                self.telemetry.last_recv = (self.clock)();
                                if let Some(event) = self.dispatch(command, &payload)? {
                                    events.push(event);
                                }
                            }
                        }
                        None => self.decoder.feed(&scratch[..n]),
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(SessionError::Io(e)),
            }
            if self.v2.is_none() {
                while let Some((command, payload)) = self.decoder.next_frame()? {
                    // Whole wire frame: payload plus the 24-byte header.
                    *self
                        .telemetry
                        .recv_by_msg
                        .entry(command.name().to_string())
                        .or_insert(0) += payload.len() as u64 + 24;
                    self.telemetry.last_recv = (self.clock)();
                    if let Some(event) = self.dispatch(command, &payload)? {
                        events.push(event);
                    }
                }
            }
        }
        self.flush()?;
        Ok(events)
    }

    /// One decoded frame → state transitions + session-level replies.
    /// Returns `Some(event)` when the caller should see the message.
    fn dispatch(
        &mut self,
        command: Command,
        payload: &[u8],
    ) -> Result<Option<SessionEvent>, SessionError> {
        if self.state == Handshake::AwaitVersion && command.name() != "version" {
            return Ok(None); // dropped, like Core's pre-version messages
        }
        let message = Message::decode(&command, payload)?;
        match (&self.state, message) {
            (Handshake::AwaitVersion, Message::Version(v)) => {
                self.peer = Some(PeerInfo {
                    version: v.version,
                    services: v.services,
                    start_height: v.start_height,
                    user_agent: v.user_agent.clone(),
                    relay: v.relay,
                    wtxid_relay: false,
                    addrv2: false,
                    recon: None,
                });
                // ProcessMessage(VERSION)'s reply burst: inbound answers
                // with our version first, then negotiation + verack.
                if !self.outbound {
                    self.send(&Message::Version(self.our_version.clone()))?;
                }
                self.send(&Message::WtxidRelay)?;
                self.send(&Message::SendAddrV2)?;
                self.send(&Message::SendRecon(crate::message::SendRecon {
                    is_sender: true,
                    is_responder: true,
                    version: crate::recon::RECON_VERSION,
                    // Per-connection salt — session id mixes process
                    // entropy so a peer cannot precompute short-ids.
                    salt: self.recon_salt,
                }))?;
                self.send(&Message::Verack)?;
                self.state = Handshake::AwaitVerack;
                Ok(Some(SessionEvent::Message(Message::Version(v))))
            }
            (_, Message::Version(_)) => Err(SessionError::DuplicateVersion),
            (Handshake::AwaitVerack, Message::Verack) => {
                self.state = Handshake::Done;
                Ok(Some(SessionEvent::Established))
            }
            (_, Message::Verack) => Ok(None), // redundant or premature verack
            (_, Message::Ping(nonce)) => {
                self.send(&Message::Pong(nonce))?;
                Ok(None) // pings are transport liveness, not sync data
            }
            (_, Message::WtxidRelay) => {
                if self.state == Handshake::Done {
                    return Err(SessionError::LateNegotiation);
                }
                if let Some(p) = &mut self.peer {
                    p.wtxid_relay = true;
                }
                Ok(None)
            }
            (_, Message::SendAddrV2) => {
                if self.state == Handshake::Done {
                    return Err(SessionError::LateNegotiation);
                }
                if let Some(p) = &mut self.peer {
                    p.addrv2 = true;
                }
                Ok(None)
            }
            (_, Message::SendRecon(r)) => {
                if self.state == Handshake::Done {
                    return Err(SessionError::LateNegotiation);
                }
                if let Some(p) = &mut self.peer {
                    p.recon = Some(r);
                }
                Ok(None)
            }
            (_, msg) => Ok(Some(SessionEvent::Message(msg))),
        }
    }
}

/// Builds the `version` message a fresh session sends. `nonce` should be a
/// random per-instance value (loopback detection); `start_height` is our
/// best height; `addr_recv` is the peer's address as observed. `now` is
/// the version's `timestamp` — Core's `GetTime`, so callers carrying a
/// mockable clock pass it; others pass [`wall_epoch()`].
#[must_use]
pub fn build_version(nonce: u64, start_height: i32, addr_recv: NetAddr, now: i64) -> Version {
    Version {
        version: PROTOCOL_VERSION,
        services: OUR_SERVICES,
        timestamp: now,
        addr_recv,
        addr_from: NetAddr::unspecified(),
        nonce,
        user_agent: "/Avila:0.1.0/".to_string(),
        start_height,
        relay: false, // a sync node doesn't ask for tx relay
    }
}

impl PeerSession<TcpStream> {
    /// `connect` + `initiate` for a real TCP endpoint. Blocking mode is the
    /// caller's choice — `set_nonblocking` before constructing for a
    /// multiplexed driver.
    ///
    /// # Errors
    /// [`SessionError`] on connect failure or a failed initial queue.
    pub fn connect(
        addr: std::net::SocketAddr,
        magic: [u8; 4],
        our_version: Version,
        send_budget: usize,
        timeout: Duration,
    ) -> Result<Self, SessionError> {
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_nodelay(true)?;
        Self::initiate(stream, magic, our_version, send_budget)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::bip324;
    use crate::message::GetHeaders;
    use avila_consensus::hash::BlockHash;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda]; // regtest
    const BUDGET: usize = 1 << 20;

    use crate::testpipe;

    fn version(start_height: i32) -> Version {
        Version {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK,
            timestamp: 1_800_000_000,
            addr_recv: NetAddr::unspecified(),
            addr_from: NetAddr::unspecified(),
            nonce: 42,
            user_agent: "/peer:0.0/".to_string(),
            start_height,
            relay: true,
        }
    }

    #[test]
    fn outbound_sends_version_first() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(1, 500, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        )
        .unwrap();
        us.poll().unwrap();
        let sent = testpipe::drain(&mut peer_end, MAGIC);
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            Message::Version(v) => {
                assert_eq!(v.start_height, 500);
                assert_eq!(v.services, OUR_SERVICES);
            }
            other => panic!("expected version, got {other:?}"),
        }
    }

    #[test]
    fn outbound_full_handshake() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(1, 500, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        )
        .unwrap();
        us.poll().unwrap();
        // Peer's view: exactly one version message.
        let sent = testpipe::drain(&mut peer_end, MAGIC);
        assert_eq!(sent.len(), 1);
        assert!(matches!(sent[0], Message::Version(_)));

        // Peer replies: version → (our wtxidrelay, sendaddrv2, verack) → verack.
        testpipe::inject(&mut peer_end, MAGIC, &Message::Version(version(600)));
        let events = us.poll().unwrap();
        let peer_sent = testpipe::drain(&mut peer_end, MAGIC);
        let names: Vec<&str> = peer_sent.iter().map(|m| m.command_name()).collect();
        assert_eq!(names, ["wtxidrelay", "sendaddrv2", "sendrecon", "verack"]);
        assert!(!us.established());

        testpipe::inject(&mut peer_end, MAGIC, &Message::Verack);
        let events2 = us.poll().unwrap();
        assert!(us.established());
        assert!(events2.contains(&SessionEvent::Established));
        let _ = events;
    }

    #[test]
    fn inbound_handshake_bursts_on_version() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(2, 500, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        );
        us.poll().unwrap();
        assert!(testpipe::drain(&mut peer_end, MAGIC).is_empty()); // silent until their version

        testpipe::inject(&mut peer_end, MAGIC, &Message::Version(version(600)));
        let events = us.poll().unwrap();
        let sent = testpipe::drain(&mut peer_end, MAGIC);
        let names: Vec<&str> = sent.iter().map(|m| m.command_name()).collect();
        assert_eq!(names, ["version", "wtxidrelay", "sendaddrv2", "sendrecon", "verack"]);
        assert!(matches!(
            events[0],
            SessionEvent::Message(Message::Version(_))
        ));

        testpipe::inject(&mut peer_end, MAGIC, &Message::Verack);
        assert!(us.poll().unwrap().contains(&SessionEvent::Established));
    }

    #[test]
    fn telemetry_counts_wire_bytes_by_command() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(6, 0, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        );
        us.poll().unwrap();
        testpipe::inject(&mut peer_end, MAGIC, &Message::Version(version(1)));
        us.poll().unwrap();
        testpipe::inject(&mut peer_end, MAGIC, &Message::Verack);
        testpipe::inject(&mut peer_end, MAGIC, &Message::GetAddr);
        us.poll().unwrap();

        let t = us.telemetry();
        let vframe = Message::Version(version(1)).encode().len() + 24;
        // version + verack + getaddr frames, counted at the wire.
        assert_eq!(t.bytes_recv as usize, vframe + 24 + 24);
        assert!(t.bytes_sent > 0);
        assert_eq!(t.recv_by_msg["version"] as usize, vframe);
        assert_eq!(t.recv_by_msg["getaddr"], 24);
        assert_eq!(t.sent_by_msg["verack"], 24);
        assert!(t.sent_by_msg["version"] > 24);
        assert!(t.connected > 0 && t.last_send > 0 && t.last_recv > 0);
        assert_ne!(t.session_id, 0);
    }

    #[test]
    fn pre_version_traffic_is_dropped_not_fatal() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(3, 0, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        );
        testpipe::inject(&mut peer_end, MAGIC, &Message::GetAddr);
        testpipe::inject(&mut peer_end, MAGIC, &Message::Ping(7));
        // Ignored, no disconnect — the poll completes without error.
        us.poll().unwrap();
        assert!(!us.established());
        assert!(testpipe::drain(&mut peer_end, MAGIC).is_empty());
    }

    #[test]
    fn duplicate_version_disconnects() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(4, 0, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        );
        testpipe::inject(&mut peer_end, MAGIC, &Message::Version(version(1)));
        us.poll().unwrap();
        testpipe::inject(&mut peer_end, MAGIC, &Message::Version(version(1)));
        assert_eq!(
            us.poll().unwrap_err().to_string(),
            "duplicate version message"
        );
    }

    #[test]
    fn wtxidrelay_after_verack_disconnects() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(5, 0, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        );
        testpipe::inject(&mut peer_end, MAGIC, &Message::Version(version(1)));
        us.poll().unwrap();
        testpipe::inject(&mut peer_end, MAGIC, &Message::Verack);
        us.poll().unwrap();
        testpipe::inject(&mut peer_end, MAGIC, &Message::WtxidRelay);
        assert_eq!(
            us.poll().unwrap_err().to_string(),
            "negotiation message after handshake completed"
        );
    }

    #[test]
    fn ping_is_answered_at_session_layer() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(6, 0, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        );
        testpipe::inject(&mut peer_end, MAGIC, &Message::Version(version(1)));
        us.poll().unwrap();
        testpipe::drain(&mut peer_end, MAGIC);
        testpipe::inject(&mut peer_end, MAGIC, &Message::Ping(0xfeed_beef));
        let events = us.poll().unwrap();
        assert!(events.is_empty()); // ping produces no caller event
        assert_eq!(
            testpipe::drain(&mut peer_end, MAGIC),
            vec![Message::Pong(0xfeed_beef)]
        );
    }

    #[test]
    fn send_budget_is_enforced() {
        let (us_end, _peer_end) = testpipe::pair();
        // A budget smaller than one version frame can't even start the
        // handshake — `initiate` fails rather than queueing past the cap.
        assert!(
            PeerSession::initiate(
                us_end,
                MAGIC,
                build_version(7, 0, NetAddr::unspecified(), wall_epoch()),
                64,
            )
            .is_err()
        );
    }

    #[test]
    fn getheaders_reaches_the_caller() {
        let (us_end, mut peer_end) = testpipe::pair();
        let mut us = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(8, 0, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        )
        .unwrap();
        testpipe::inject(&mut peer_end, MAGIC, &Message::Version(version(1)));
        testpipe::inject(&mut peer_end, MAGIC, &Message::Verack);
        us.poll().unwrap();
        let gh = Message::GetHeaders(GetHeaders {
            locator: vec![BlockHash::ZERO],
            stop: BlockHash::ZERO,
        });
        testpipe::inject(&mut peer_end, MAGIC, &gh);
        let events = us.poll().unwrap();
        assert_eq!(events, vec![SessionEvent::Message(gh)]);
    }

    #[test]
    fn peer_hangup_is_eof() {
        let (us_end, peer_end) = testpipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(9, 0, NetAddr::unspecified(), wall_epoch()),
            BUDGET,
        );
        drop(peer_end);
        assert_eq!(
            us.poll().unwrap_err().to_string(),
            "peer closed the connection"
        );
    }

    /// Full BIP324 session over an in-memory pipe: ellswift exchange
    /// interleaved start/respond/finish, then the v2 packet channel
    /// carries version → verack → ping like the cleartext wire.
    #[test]
    fn v2_session_handshakes_and_speaks() {
        let (mut a, mut b) = testpipe::pair();

        // Phase-interleaved handshake: initiator key+garbage →
        // responder key+garbage+terminator+version-pkt → ECDH.
        let pending = bip324::start_handshake(&mut a).unwrap();
        let ch_b = bip324::respond_handshake(&mut b, MAGIC).unwrap();
        let bip324::Handshake::V2(cipher_a, garbage_a) =
            bip324::finish_handshake(&mut a, pending, MAGIC).unwrap()
        else {
            panic!("v1 fallback on a v2 peer");
        };
        let mut ch_a = bip324::V2Channel::new(cipher_a, garbage_a);
        let tail = ch_a.handshake_tail();
        a.write_all(&tail).unwrap();

        let mut us =
            PeerSession::initiate_v2_channel(a, MAGIC, version(100), BUDGET, ch_a).unwrap();
        let mut them = PeerSession::accept_v2_channel(b, MAGIC, version(99), BUDGET, ch_b);

        assert_eq!(us.transport_protocol(), "v2");
        // Both sides derived the same session id.
        assert_eq!(us.v2_session_id(), them.v2_session_id());

        // Our queued version flushes onto the wire; this poll also
        // consumes the responder's garbage/terminator/version-packet.
        us.poll().unwrap();
        // Responder reads our version, then replies.
        let events = them.poll().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::Message(Message::Version(_)))),
            "initiator version didn't decrypt: {events:?}"
        );
        let events = us.poll().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::Message(Message::Version(_)))),
            "responder version didn't decrypt: {events:?}"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::Established))
        );
        assert!(us.established());
        let events = them.poll().unwrap();
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::Established))
        );

        // A post-handshake message rides the encrypted channel.
        them.send(&Message::Ping(0xdead_beef)).unwrap();
        us.poll().unwrap();
        them.poll().unwrap();
    }

    /// A peer answering the v2 handshake with the v1 `version` prefix
    /// is detected — the caller falls back to cleartext.
    #[test]
    fn v1_only_peer_triggers_fallback() {
        let (mut a, mut b) = testpipe::pair();
        let pending = bip324::start_handshake(&mut a).unwrap();
        // The "peer" speaks v1: first bytes are `magic||version…`.
        testpipe::inject(&mut b, MAGIC, &Message::Version(version(1)));
        match bip324::finish_handshake(&mut a, pending, MAGIC).unwrap() {
            bip324::Handshake::V1Fallback => {}
            _ => panic!("v1 peer not detected"),
        }
    }

    /// A v1 peer aborts the moment our ellswift bytes fail its magic
    /// check — an immediate EOF/RST means `ShouldReconnectV1` (Core
    /// reconnects v1 while the receive buffer is still empty).
    #[test]
    fn v1_peer_eof_triggers_fallback() {
        let (mut a, b) = testpipe::pair();
        let pending = bip324::start_handshake(&mut a).unwrap();
        drop(b); // v1 peer slams the door on our garbage
        match bip324::finish_handshake(&mut a, pending, MAGIC).unwrap() {
            bip324::Handshake::V1Fallback => {}
            _ => panic!("eof before any bytes not detected"),
        }
    }
}

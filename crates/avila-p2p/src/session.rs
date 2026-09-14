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
}

/// A single peer connection's protocol state.
pub struct PeerSession<S> {
    stream: S,
    magic: [u8; 4],
    decoder: FrameDecoder,
    send_buf: VecDeque<u8>,
    state: Handshake,
    our_version: Version,
    /// Whether we initiated the connection (Core's outbound vs inbound).
    outbound: bool,
    peer: Option<PeerInfo>,
    connected_at: Instant,
    /// Maximum bytes allowed outstanding in `send_buf`.
    send_budget: usize,
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
            send_budget,
        }
    }

    /// The peer's `version` fields once received.
    #[must_use]
    pub fn peer(&self) -> Option<&PeerInfo> {
        self.peer.as_ref()
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
        let frame = encode_frame(self.magic, command, &message.encode());
        if self.send_buf.len() + frame.len() > self.send_budget {
            return Err(SessionError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "per-peer send budget exhausted",
            )));
        }
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
            let n = self.stream.write(self.send_buf.make_contiguous())?;
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
                Ok(n) => self.decoder.feed(&scratch[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(SessionError::Io(e)),
            }
            while let Some((command, payload)) = self.decoder.next_frame()? {
                if let Some(event) = self.dispatch(command, &payload)? {
                    events.push(event);
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
                });
                // ProcessMessage(VERSION)'s reply burst: inbound answers
                // with our version first, then negotiation + verack.
                if !self.outbound {
                    self.send(&Message::Version(self.our_version.clone()))?;
                }
                self.send(&Message::WtxidRelay)?;
                self.send(&Message::SendAddrV2)?;
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
            (_, msg) => Ok(Some(SessionEvent::Message(msg))),
        }
    }
}

/// Builds the `version` message a fresh session sends. `nonce` should be a
/// random per-instance value (loopback detection); `start_height` is our
/// best height; `addr_recv` is the peer's address as observed.
#[must_use]
pub fn build_version(nonce: u64, start_height: i32, addr_recv: NetAddr) -> Version {
    Version {
        version: PROTOCOL_VERSION,
        services: OUR_SERVICES,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
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
    use crate::codec::encode_frame;
    use crate::message::GetHeaders;
    use avila_consensus::hash::BlockHash;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    const MAGIC: [u8; 4] = [0xfa, 0xbf, 0xb5, 0xda]; // regtest
    const BUDGET: usize = 1 << 20;

    /// An in-memory full-duplex pipe end: never blocks on write, `WouldBlock`
    /// on empty read, EOF once the peer end drops.
    struct End {
        /// Bytes this end reads (written by the other end).
        inbox: Rc<RefCell<VecDeque<u8>>>,
        /// Bytes this end writes (read by the other end).
        outbox: Rc<RefCell<VecDeque<u8>>>,
        /// Whether the peer end is still alive.
        peer_open: Rc<Cell<bool>>,
        /// This end's liveness flag, observed by the peer.
        alive: Rc<Cell<bool>>,
    }

    impl Drop for End {
        fn drop(&mut self) {
            self.alive.set(false);
        }
    }

    struct Pipe;

    impl Pipe {
        fn pair() -> (End, End) {
            let a_to_b = Rc::new(RefCell::new(VecDeque::new()));
            let b_to_a = Rc::new(RefCell::new(VecDeque::new()));
            let a_open = Rc::new(Cell::new(true));
            let b_open = Rc::new(Cell::new(true));
            (
                End {
                    inbox: b_to_a.clone(),
                    outbox: a_to_b.clone(),
                    peer_open: b_open.clone(),
                    alive: a_open.clone(),
                },
                End {
                    inbox: a_to_b,
                    outbox: b_to_a,
                    peer_open: a_open,
                    alive: b_open,
                },
            )
        }
    }

    impl Read for End {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut inbox = self.inbox.borrow_mut();
            if inbox.is_empty() {
                return if self.peer_open.get() {
                    Err(io::Error::new(io::ErrorKind::WouldBlock, "empty pipe"))
                } else {
                    Ok(0) // peer hung up
                };
            }
            let n = buf.len().min(inbox.len());
            for slot in &mut buf[..n] {
                *slot = inbox.pop_front().unwrap_or(0);
            }
            Ok(n)
        }
    }

    impl Write for End {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.outbox.borrow_mut().extend(buf.iter().copied());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

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

    /// What the other end of the pipe would receive, decoded to messages.
    fn drain(end: &mut End) -> Vec<Message> {
        let mut out = Vec::new();
        let mut buf = [0u8; 8192];
        let mut dec = FrameDecoder::new(MAGIC);
        while let Ok(n) = end.read(&mut buf) {
            dec.feed(&buf[..n]);
        }
        while let Ok(Some((cmd, payload))) = dec.next_frame() {
            out.push(Message::decode(&cmd, &payload).unwrap());
        }
        out
    }

    /// Pushes a message into the session's receive path as wire bytes.
    fn inject(end: &mut End, msg: &Message) {
        let frame = encode_frame(MAGIC, msg.command().unwrap(), &msg.encode());
        end.write_all(&frame).unwrap();
    }

    #[test]
    fn outbound_sends_version_first() {
        let (us_end, mut peer_end) = Pipe::pair();
        let mut us = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(1, 500, NetAddr::unspecified()),
            BUDGET,
        )
        .unwrap();
        us.poll().unwrap();
        let sent = drain(&mut peer_end);
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
        let (us_end, mut peer_end) = Pipe::pair();
        let mut us = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(1, 500, NetAddr::unspecified()),
            BUDGET,
        )
        .unwrap();
        us.poll().unwrap();
        // Peer's view: exactly one version message.
        let sent = drain(&mut peer_end);
        assert_eq!(sent.len(), 1);
        assert!(matches!(sent[0], Message::Version(_)));

        // Peer replies: version → (our wtxidrelay, sendaddrv2, verack) → verack.
        inject(&mut peer_end, &Message::Version(version(600)));
        let events = us.poll().unwrap();
        let peer_sent = drain(&mut peer_end);
        let names: Vec<&str> = peer_sent.iter().map(|m| m.command_name()).collect();
        assert_eq!(names, ["wtxidrelay", "sendaddrv2", "verack"]);
        assert!(!us.established());

        inject(&mut peer_end, &Message::Verack);
        let events2 = us.poll().unwrap();
        assert!(us.established());
        assert!(events2.contains(&SessionEvent::Established));
        let _ = events;
    }

    #[test]
    fn inbound_handshake_bursts_on_version() {
        let (us_end, mut peer_end) = Pipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(2, 500, NetAddr::unspecified()),
            BUDGET,
        );
        us.poll().unwrap();
        assert!(drain(&mut peer_end).is_empty()); // silent until their version

        inject(&mut peer_end, &Message::Version(version(600)));
        let events = us.poll().unwrap();
        let sent = drain(&mut peer_end);
        let names: Vec<&str> = sent.iter().map(|m| m.command_name()).collect();
        assert_eq!(names, ["version", "wtxidrelay", "sendaddrv2", "verack"]);
        assert!(matches!(
            events[0],
            SessionEvent::Message(Message::Version(_))
        ));

        inject(&mut peer_end, &Message::Verack);
        assert!(us.poll().unwrap().contains(&SessionEvent::Established));
    }

    #[test]
    fn pre_version_traffic_is_dropped_not_fatal() {
        let (us_end, mut peer_end) = Pipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(3, 0, NetAddr::unspecified()),
            BUDGET,
        );
        inject(&mut peer_end, &Message::GetAddr);
        inject(&mut peer_end, &Message::Ping(7));
        // Ignored, no disconnect — the poll completes without error.
        us.poll().unwrap();
        assert!(!us.established());
        assert!(drain(&mut peer_end).is_empty());
    }

    #[test]
    fn duplicate_version_disconnects() {
        let (us_end, mut peer_end) = Pipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(4, 0, NetAddr::unspecified()),
            BUDGET,
        );
        inject(&mut peer_end, &Message::Version(version(1)));
        us.poll().unwrap();
        inject(&mut peer_end, &Message::Version(version(1)));
        assert_eq!(
            us.poll().unwrap_err().to_string(),
            "duplicate version message"
        );
    }

    #[test]
    fn wtxidrelay_after_verack_disconnects() {
        let (us_end, mut peer_end) = Pipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(5, 0, NetAddr::unspecified()),
            BUDGET,
        );
        inject(&mut peer_end, &Message::Version(version(1)));
        us.poll().unwrap();
        inject(&mut peer_end, &Message::Verack);
        us.poll().unwrap();
        inject(&mut peer_end, &Message::WtxidRelay);
        assert_eq!(
            us.poll().unwrap_err().to_string(),
            "negotiation message after handshake completed"
        );
    }

    #[test]
    fn ping_is_answered_at_session_layer() {
        let (us_end, mut peer_end) = Pipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(6, 0, NetAddr::unspecified()),
            BUDGET,
        );
        inject(&mut peer_end, &Message::Version(version(1)));
        us.poll().unwrap();
        drain(&mut peer_end);
        inject(&mut peer_end, &Message::Ping(0xfeed_beef));
        let events = us.poll().unwrap();
        assert!(events.is_empty()); // ping produces no caller event
        assert_eq!(drain(&mut peer_end), vec![Message::Pong(0xfeed_beef)]);
    }

    #[test]
    fn send_budget_is_enforced() {
        let (us_end, _peer_end) = Pipe::pair();
        // A budget smaller than one version frame can't even start the
        // handshake — `initiate` fails rather than queueing past the cap.
        assert!(
            PeerSession::initiate(
                us_end,
                MAGIC,
                build_version(7, 0, NetAddr::unspecified()),
                64,
            )
            .is_err()
        );
    }

    #[test]
    fn getheaders_reaches_the_caller() {
        let (us_end, mut peer_end) = Pipe::pair();
        let mut us = PeerSession::initiate(
            us_end,
            MAGIC,
            build_version(8, 0, NetAddr::unspecified()),
            BUDGET,
        )
        .unwrap();
        inject(&mut peer_end, &Message::Version(version(1)));
        inject(&mut peer_end, &Message::Verack);
        us.poll().unwrap();
        let gh = Message::GetHeaders(GetHeaders {
            locator: vec![BlockHash::ZERO],
            stop: BlockHash::ZERO,
        });
        inject(&mut peer_end, &gh);
        let events = us.poll().unwrap();
        assert_eq!(events, vec![SessionEvent::Message(gh)]);
    }

    #[test]
    fn peer_hangup_is_eof() {
        let (us_end, peer_end) = Pipe::pair();
        let mut us = PeerSession::accept(
            us_end,
            MAGIC,
            build_version(9, 0, NetAddr::unspecified()),
            BUDGET,
        );
        drop(peer_end);
        assert_eq!(
            us.poll().unwrap_err().to_string(),
            "peer closed the connection"
        );
    }
}

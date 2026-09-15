//! Bounded Bitcoin P2P wire protocol (G3's first slice).
//!
//! Two layers, matching Core's `net`/`netmessagemaker` split:
//!
//! * [`codec`] — the 24-byte message header (`magic | command | length |
//!   checksum`) and an incremental, bounded frame decoder. Payload length is
//!   capped at Core's `MAX_PROTOCOL_MESSAGE_LENGTH` (4 MiB) and the
//!   sha256d checksum is verified before a payload is yielded.
//! * [`message`] — the sync-relevant message set: the `version`/`verack`
//!   handshake, `ping`/`pong`, `sendheaders`/`wtxidrelay`/`sendaddrv2`/
//!   `feefilter`, `getheaders`/`headers`, `inv`/`getdata`/`notfound`,
//!   `block`/`tx`, `getaddr`/`addr`/`addrv2`, `mempool`, and the legacy
//!   `reject`. Unknown commands decode to [`Message::Unknown`] — Core ignores
//!   them the same way.
//!
//! * [`session`] — one peer's handshake choreography and message pump over
//!   any `Read + Write` transport, mirroring `net_processing`'s
//!   `version`/`verack` ordering.
//!
//! Everything here is transport plumbing; no consensus verdict is produced
//! or consumed at this layer. The `headers` payload decodes to
//! [`avila_consensus::header::BlockHeader`], which `Chainstate::accept_header`
//! validates — the wire format and the rule check stay separate.

pub mod addrman;
pub mod banman;
pub mod codec;
pub mod manager;
pub mod message;
pub mod proxy;
pub mod session;
pub mod sync;

#[cfg(test)]
pub(crate) mod testchain;
#[cfg(test)]
pub(crate) mod testpipe;

pub use addrman::{AddrBook, AddrInfo};
pub use codec::{Command, FrameDecoder, FrameError, HEADER_LEN, MAX_MESSAGE_PAYLOAD};
pub use manager::{DisconnectReason, NetEvent, PeerManager};
pub use message::{AddrEntry, GetHeaders, InvType, InvVector, Message, NetAddr, Reject, Version};
pub use session::{
    HANDSHAKE_TIMEOUT, PeerInfo, PeerSession, SessionError, SessionEvent, build_version,
};
pub use sync::{BlockOutcome, HeadersOutcome, PeerSync, SyncError};

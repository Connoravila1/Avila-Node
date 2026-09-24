//! P2P message payloads — encode/decode for the commands a synchronizing
//! node speaks, in Core's serialization order.
//!
//! Every decode runs through the bounded consensus [`Decoder`]; counts and
//! strings are capacity-checked against the payload actually present, so a
//! hostile frame can never drive an oversized allocation.

use avila_consensus::block::Block;
use avila_consensus::encode::{Decoder, write_compact_size, write_var_bytes};
use avila_consensus::hash::BlockHash;
use avila_consensus::header::BlockHeader;
use avila_consensus::transaction::Transaction;
use thiserror::Error;

use crate::codec::Command;

/// `NODE_NETWORK` — the peer serves full blocks.
pub const NODE_NETWORK: u64 = 1;
/// `NODE_WITNESS` — the peer can serve witness data.
pub const NODE_WITNESS: u64 = 1 << 3;
/// `NODE_COMPACT_FILTERS` — the peer serves BIP158 filters.
pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;
/// `NODE_NETWORK_LIMITED` — the peer serves only the recent ~288 blocks.
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;
/// `NODE_P2P_V2` — the peer supports the BIP324 encrypted transport.
pub const NODE_P2P_V2: u64 = 1 << 11;

/// The protocol version we speak — Core v29's `PROTOCOL_VERSION` is 70016.
pub const PROTOCOL_VERSION: i32 = 70016;

/// `MSG_WITNESS_FLAG` — OR'd into an inv type to request witness data.
pub const MSG_WITNESS_FLAG: u32 = 0x4000_0000;
/// `MSG_WITNESS_BLOCK` — a `getdata` type asking for the block with its
/// witnesses. Requesting plain `MSG_BLOCK` on a segwit chain yields a
/// witness-stripped serialization that fails the witness-commitment check —
/// the same rejection Core produces.
pub const MSG_WITNESS_BLOCK: u32 = MSG_WITNESS_FLAG | 2;

/// A network address as serialized in `version`, `addr` and `addrv2`
/// payloads. IPv4 peers appear IPv4-mapped, as on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NetAddr {
    /// `nServices` flags.
    pub services: u64,
    /// The 16 wire bytes of the address (v4-mapped or v6).
    pub ip: [u8; 16],
    /// Port, host order.
    pub port: u16,
}

impl NetAddr {
    /// An unspecified address — the placeholder Core uses for `addr_recv`.
    #[must_use]
    pub const fn unspecified() -> Self {
        Self {
            services: 0,
            ip: [0; 16],
            port: 0,
        }
    }
}

/// One `addr` payload entry — a timestamped [`NetAddr`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddrEntry {
    /// `nTime` — when the peer was last seen; ignored for relay on modern
    /// Core but carried for wire fidelity.
    pub time: u32,
    /// The address.
    pub addr: NetAddr,
}

/// One `addrv2` (BIP155) entry. The address stays opaque bytes — network IDs
/// beyond IPv4/IPv6 round-trip without parsing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AddrV2Entry {
    /// `nTime`.
    pub time: u32,
    /// `nServices`, compactsize-encoded on the wire.
    pub services: u64,
    /// BIP155 network identifier byte.
    pub network: u8,
    /// The raw address bytes for `network`.
    pub addr: Vec<u8>,
    /// Port, host order.
    pub port: u16,
}

/// `inv`/`getdata`/`notfound` element types (Core's `MSG_*` values).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InvType {
    /// `MSG_TX`.
    Tx,
    /// `MSG_BLOCK`.
    Block,
    /// `MSG_FILTERED_BLOCK`.
    FilteredBlock,
    /// `MSG_CMPCT_BLOCK`.
    CompactBlock,
    /// `MSG_WTX`.
    Wtx,
    /// `MSG_WITNESS_BLOCK` — a block with witness data.
    WitnessBlock,
    /// `MSG_WITNESS_TX` — a transaction by txid, witness serialization.
    WitnessTx,
    /// Otherwise unrecognized — kept for round-trip fidelity; the
    /// requester, not the codec, assigns meaning.
    Other(u32),
}

impl InvType {
    fn to_u32(self) -> u32 {
        match self {
            Self::Tx => 1,
            Self::Block => 2,
            Self::FilteredBlock => 3,
            Self::CompactBlock => 4,
            Self::Wtx => 5,
            Self::WitnessBlock => MSG_WITNESS_BLOCK,
            Self::WitnessTx => MSG_WITNESS_FLAG | 1,
            Self::Other(v) => v,
        }
    }
}

/// One element of an `inv`/`getdata`/`notfound` vector.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InvVector {
    /// What `hash` names.
    pub inv_type: InvType,
    /// The txid/wtxid/block hash.
    pub hash: BlockHash,
}

/// The `getheaders` payload — a locator plus a stop hash (Core's
/// `CBlockLocator` flattens to a bare hash vector on the wire).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GetHeaders {
    /// The sender's locator, newest first.
    pub locator: Vec<BlockHash>,
    /// Stop before this hash (all-zero = run to the peer's tip).
    pub stop: BlockHash,
}

/// Shared request shape of `getcfilters`/`getcfheaders`/`getcfcheckpt`
/// — BIP157's `filter_type + start_height + stop_hash` triple.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CFRange {
    /// BIP157 filter type — 0 is basic (the only defined type).
    pub filter_type: u8,
    /// First block height to serve.
    pub start_height: u32,
    /// Last block to serve, by hash.
    pub stop_hash: BlockHash,
}

/// The `cfilter` payload — one block's encoded filter.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CFilter {
    /// BIP157 filter type.
    pub filter_type: u8,
    /// The block this filter belongs to.
    pub block_hash: BlockHash,
    /// The GCS-encoded filter bytes.
    pub filter: Vec<u8>,
}

/// The `cfheaders` payload — filter headers for `start..=stop`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CFHeaders {
    /// BIP157 filter type.
    pub filter_type: u8,
    /// The last block in the range.
    pub stop_hash: BlockHash,
    /// Filter header of the block *before* the range (all-zero when
    /// the range starts at genesis — BIP157).
    pub prev_filter_header: [u8; 32],
    /// One filter header per block in the range.
    pub filter_hashes: Vec<[u8; 32]>,
}

/// The `getcfcheckpt` payload — filter type plus the stop hash.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CFCheckptReq {
    /// BIP157 filter type.
    pub filter_type: u8,
    /// The last block covered.
    pub stop_hash: BlockHash,
}

/// The `cfcheckpt` payload — filter headers at 1000-block intervals.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CFCheckpt {
    /// BIP157 filter type.
    pub filter_type: u8,
    /// The last block covered.
    pub stop_hash: BlockHash,
    /// Filter headers — every 1,000th height within the range.
    pub filter_headers: Vec<[u8; 32]>,
}

/// The `version` payload.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Version {
    /// Protocol version the peer speaks.
    pub version: i32,
    /// `nServices` the peer offers.
    pub services: u64,
    /// Peer-reported time.
    pub timestamp: i64,
    /// The address the peer believes we are.
    pub addr_recv: NetAddr,
    /// The address the peer advertises as its own.
    pub addr_from: NetAddr,
    /// Peer nonce — loopback detection.
    pub nonce: u64,
    /// The user-agent string.
    pub user_agent: String,
    /// Peer's claimed best height.
    pub start_height: i32,
    /// BIP37 relay preference.
    pub relay: bool,
}

/// The legacy `reject` payload (BIP61; deprecated but still seen in the wild).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reject {
    /// The command being rejected.
    pub message: String,
    /// BIP61 reject code.
    pub code: u8,
    /// Human-readable reason.
    pub reason: String,
    /// Optional extra data (e.g. the rejected object's hash).
    pub data: Vec<u8>,
}

/// One decoded P2P message.
#[derive(Clone, PartialEq, Debug)]
pub enum Message {
    /// `version`.
    Version(Version),
    /// `verack` — handshake acknowledgement.
    Verack,
    /// `ping` — expects a `pong` echo of the nonce.
    Ping(u64),
    /// `pong`.
    Pong(u64),
    /// `sendheaders` — peer prefers headers announcements over invs.
    SendHeaders,
    /// `wtxidrelay` — peer will announce transactions by wtxid (BIP339).
    WtxidRelay,
    /// `sendaddrv2` — peer understands BIP155 addresses.
    SendAddrV2,
    /// `feefilter` — minimum feerate the peer accepts, sat/kvB.
    FeeFilter(u64),
    /// `getaddr` — request for known peers.
    GetAddr,
    /// `addr` — pre-BIP155 address gossip.
    Addr(Vec<AddrEntry>),
    /// `addrv2` — BIP155 address gossip.
    AddrV2(Vec<AddrV2Entry>),
    /// `inv` — inventory announcement.
    Inv(Vec<InvVector>),
    /// `getdata` — inventory request.
    GetData(Vec<InvVector>),
    /// `notfound` — requested inventory unavailable.
    NotFound(Vec<InvVector>),
    /// `getheaders` — headers-sync request.
    GetHeaders(GetHeaders),
    /// `headers` — a headers response (each header is followed by a zero
    /// transaction-count byte, the BIP152-compatible encoding).
    Headers(Vec<BlockHeader>),
    /// `block` — a full block.
    Block(Block),
    /// `tx` — a transaction.
    Tx(Transaction),
    /// `mempool` — request for the relay set (BIP35).
    Mempool,
    /// `getcfilters` — BIP157 request for basic filters in a range.
    GetCFilters(CFRange),
    /// `cfilter` — BIP157 filter response (one block's filter).
    CFilter(CFilter),
    /// `getcfheaders` — BIP157 request for the filter-header chain.
    GetCFHeaders(CFRange),
    /// `cfheaders` — BIP157 filter-header chain response.
    CFHeaders(CFHeaders),
    /// `getcfcheckpt` — BIP157 request for 1000-block-interval headers.
    /// Its payload is only `filter_type + stop_hash` (no range).
    GetCFCheckpt(CFCheckptReq),
    /// `cfcheckpt` — BIP157 checkpoint response.
    CFCheckpt(CFCheckpt),
    /// `reject` — BIP61 rejection notice.
    Reject(Reject),
    /// `sendrecon` — BIP330 (Erlay) reconciliation-capability handshake:
    /// roles, protocol version and the 64-bit salt that keys the
    /// connection's transaction short-ids.
    SendRecon(SendRecon),
    /// `reqrecon` — BIP330: requester opens a reconciliation round by
    /// sending its set sketch.
    ReqRecon(Vec<u8>),
    /// `sketch` — BIP330: responder's reply sketch; the requester XORs
    /// it with its own and decodes the symmetric difference.
    Sketch(Vec<u8>),
    /// `reconcildiff` — BIP330: short-ids the sender still wants (its
    /// decode misses) plus a parent-ask flag.
    ReconcilDiff {
        /// Whether the sender also asks for missing parents.
        ask_parents: u32,
        /// 32-bit short-ids the sender wants bodies for.
        short_ids: Vec<u32>,
    },
    /// `reqbisec` — BIP330: ask the peer to bisect its set when a sketch
    /// exceeds capacity (empty payload like `mempool`).
    ReqBisec,
    /// Any other command — Core ignores unknown commands; we preserve the
    /// payload so a session layer can log or drop the peer itself.
    Unknown {
        /// The command as received.
        command: String,
        /// The raw payload bytes.
        payload: Vec<u8>,
    },
}

/// Why a payload cannot decode — all indicate a malformed (or truncated)
/// message from the peer.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("malformed {command} payload: {detail}")]
pub struct PayloadError {
    /// The command being decoded.
    pub command: String,
    /// The decode failure.
    pub detail: String,
}

fn payload_err(command: &str, detail: impl std::fmt::Display) -> PayloadError {
    PayloadError {
        command: command.to_string(),
        detail: detail.to_string(),
    }
}

fn get_net_addr(d: &mut Decoder, command: &str) -> Result<NetAddr, PayloadError> {
    let services = d.read_u64_le().map_err(|e| payload_err(command, e))?;
    let ip = d.read_array::<16>().map_err(|e| payload_err(command, e))?;
    let port = u16::from_be_bytes(d.read_array::<2>().map_err(|e| payload_err(command, e))?);
    Ok(NetAddr { services, ip, port })
}

fn put_net_addr(out: &mut Vec<u8>, addr: &NetAddr) {
    out.extend_from_slice(&addr.services.to_le_bytes());
    out.extend_from_slice(&addr.ip);
    out.extend_from_slice(&addr.port.to_be_bytes());
}

fn get_inv_vector(d: &mut Decoder, command: &str) -> Result<InvVector, PayloadError> {
    let raw = d.read_u32_le().map_err(|e| payload_err(command, e))?;
    let inv_type = match raw {
        1 => InvType::Tx,
        2 => InvType::Block,
        3 => InvType::FilteredBlock,
        4 => InvType::CompactBlock,
        5 => InvType::Wtx,
        MSG_WITNESS_BLOCK => InvType::WitnessBlock,
        x if x == MSG_WITNESS_FLAG | 1 => InvType::WitnessTx,
        other => InvType::Other(other),
    };
    let hash = BlockHash::from_bytes(d.read_array::<32>().map_err(|e| payload_err(command, e))?);
    Ok(InvVector { inv_type, hash })
}

fn put_inv_vector(out: &mut Vec<u8>, inv: &InvVector) {
    out.extend_from_slice(&inv.inv_type.to_u32().to_le_bytes());
    out.extend_from_slice(inv.hash.as_bytes());
}

/// The maximum `inv`-vector size — Core's `MAX_INV_SZ` (net_processing).
const MAX_INV_SZ: u64 = 50_000;

/// BIP330 sketch payload bound — a reconciliation sketch is `4 x
/// capacity` bytes and capacities beyond ~4096 differences are decode-
/// expensive anyway; larger payloads are rejected before allocation.
const MAX_SKETCH_BYTES: usize = 64 * 1024;

/// BIP330 `reconcildiff` short-id list bound — a round asks for at most
/// the sketch capacity worth of missing txs.
const MAX_RECONCIL_IDS: u64 = 16_384;

/// `sendrecon` — BIP330 (Erlay) set-reconciliation capability
/// negotiation. Roles let a pair agree who reconciles; the 64-bit salt
/// keys this connection's transaction short-ids so a peer cannot
/// precompute collisions across links.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendRecon {
    /// Whether this node initiates reconciliation rounds.
    pub is_sender: bool,
    /// Whether this node answers reconciliation requests.
    pub is_responder: bool,
    /// Reconciliation protocol version (BIP330 defines 1).
    pub version: u32,
    /// Per-connection salt keying [`crate::recon::short_id`].
    pub salt: u64,
}

fn get_inv_list(d: &mut Decoder, command: &str) -> Result<Vec<InvVector>, PayloadError> {
    let count = d.read_compact_size().map_err(|e| payload_err(command, e))?;
    if count > MAX_INV_SZ {
        return Err(payload_err(
            command,
            format!("inv count {count} exceeds MAX_INV_SZ"),
        ));
    }
    let mut v = Vec::with_capacity(d.bounded_capacity(count, 36));
    for _ in 0..count {
        v.push(get_inv_vector(d, command)?);
    }
    Ok(v)
}

fn put_inv_list(out: &mut Vec<u8>, invs: &[InvVector]) {
    write_compact_size(out, invs.len() as u64);
    for inv in invs {
        put_inv_vector(out, inv);
    }
}

/// The maximum headers per `headers` message — Core's `MAX_HEADERS_RESULTS`.
pub const MAX_HEADERS_RESULTS: u64 = 2_000;

impl Message {
    /// The command name this message sends under.
    #[must_use]
    pub fn command_name(&self) -> &str {
        match self {
            Self::Version(_) => "version",
            Self::Verack => "verack",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::SendHeaders => "sendheaders",
            Self::WtxidRelay => "wtxidrelay",
            Self::SendAddrV2 => "sendaddrv2",
            Self::FeeFilter(_) => "feefilter",
            Self::GetAddr => "getaddr",
            Self::Addr(_) => "addr",
            Self::AddrV2(_) => "addrv2",
            Self::Inv(_) => "inv",
            Self::GetData(_) => "getdata",
            Self::NotFound(_) => "notfound",
            Self::GetHeaders(_) => "getheaders",
            Self::Headers(_) => "headers",
            Self::Block(_) => "block",
            Self::Tx(_) => "tx",
            Self::Mempool => "mempool",
            Self::GetCFilters(_) => "getcfilters",
            Self::CFilter(_) => "cfilter",
            Self::GetCFHeaders(_) => "getcfheaders",
            Self::CFHeaders(_) => "cfheaders",
            Self::GetCFCheckpt(_) => "getcfcheckpt",
            Self::CFCheckpt(_) => "cfcheckpt",
            Self::Reject(_) => "reject",
            Self::SendRecon(_) => "sendrecon",
            Self::ReqRecon(_) => "reqrecon",
            Self::Sketch(_) => "sketch",
            Self::ReconcilDiff { .. } => "reconcildiff",
            Self::ReqBisec => "reqbisec",
            Self::Unknown { command, .. } => command.as_str(),
        }
    }

    /// The [`Command`] this message sends under. `None` only if a stored
    /// `Unknown` name cannot re-encode — decode guarantees it can, so
    /// `None` effectively means "constructed by hand with an invalid name".
    #[must_use]
    pub fn command(&self) -> Option<Command> {
        Command::new(self.command_name())
    }

    /// Encodes the payload (frame layer adds the header).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Version(v) => {
                out.extend_from_slice(&v.version.to_le_bytes());
                out.extend_from_slice(&v.services.to_le_bytes());
                out.extend_from_slice(&v.timestamp.to_le_bytes());
                put_net_addr(&mut out, &v.addr_recv);
                put_net_addr(&mut out, &v.addr_from);
                out.extend_from_slice(&v.nonce.to_le_bytes());
                write_var_bytes(&mut out, v.user_agent.as_bytes());
                out.extend_from_slice(&v.start_height.to_le_bytes());
                out.push(u8::from(v.relay));
            }
            Self::Ping(nonce) | Self::Pong(nonce) => {
                out.extend_from_slice(&nonce.to_le_bytes());
            }
            Self::FeeFilter(rate) => out.extend_from_slice(&rate.to_le_bytes()),
            Self::Addr(entries) => {
                write_compact_size(&mut out, entries.len() as u64);
                for e in entries {
                    out.extend_from_slice(&e.time.to_le_bytes());
                    put_net_addr(&mut out, &e.addr);
                }
            }
            Self::AddrV2(entries) => {
                write_compact_size(&mut out, entries.len() as u64);
                for e in entries {
                    out.extend_from_slice(&e.time.to_le_bytes());
                    write_compact_size(&mut out, e.services);
                    out.push(e.network);
                    out.push(u8::try_from(e.addr.len().min(255)).unwrap_or(0));
                    out.extend_from_slice(&e.addr);
                    out.extend_from_slice(&e.port.to_be_bytes());
                }
            }
            Self::Inv(v) | Self::GetData(v) | Self::NotFound(v) => put_inv_list(&mut out, v),
            Self::GetHeaders(gh) => {
                out.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
                write_compact_size(&mut out, gh.locator.len() as u64);
                for hash in &gh.locator {
                    out.extend_from_slice(hash.as_bytes());
                }
                out.extend_from_slice(gh.stop.as_bytes());
            }
            Self::Headers(headers) => {
                write_compact_size(&mut out, headers.len() as u64);
                for header in headers {
                    out.extend_from_slice(&header.encode());
                    out.push(0); // BIP152-style zero txn count
                }
            }
            Self::GetCFilters(r) | Self::GetCFHeaders(r) => {
                out.push(r.filter_type);
                out.extend_from_slice(&r.start_height.to_le_bytes());
                out.extend_from_slice(r.stop_hash.as_bytes());
            }
            Self::GetCFCheckpt(r) => {
                out.push(r.filter_type);
                out.extend_from_slice(r.stop_hash.as_bytes());
            }
            Self::CFilter(f) => {
                out.push(f.filter_type);
                out.extend_from_slice(f.block_hash.as_bytes());
                write_compact_size(&mut out, f.filter.len() as u64);
                out.extend_from_slice(&f.filter);
            }
            Self::CFHeaders(h) => {
                out.push(h.filter_type);
                out.extend_from_slice(h.stop_hash.as_bytes());
                out.extend_from_slice(&h.prev_filter_header);
                write_compact_size(&mut out, h.filter_hashes.len() as u64);
                for fh in &h.filter_hashes {
                    out.extend_from_slice(fh);
                }
            }
            Self::CFCheckpt(c) => {
                out.push(c.filter_type);
                out.extend_from_slice(c.stop_hash.as_bytes());
                write_compact_size(&mut out, c.filter_headers.len() as u64);
                for fh in &c.filter_headers {
                    out.extend_from_slice(fh);
                }
            }
            Self::Block(block) => out = block.encode(),
            Self::Tx(tx) => out = tx.encode(),
            Self::Reject(r) => {
                write_var_bytes(&mut out, r.message.as_bytes());
                out.push(r.code);
                write_var_bytes(&mut out, r.reason.as_bytes());
                out.extend_from_slice(&r.data);
            }
            Self::Unknown { payload, .. } => out.extend_from_slice(payload),
            Self::Verack
            | Self::SendHeaders
            | Self::WtxidRelay
            | Self::SendAddrV2
            | Self::GetAddr
            | Self::Mempool
            | Self::ReqBisec => {}
            Self::SendRecon(r) => {
                out.push(u8::from(r.is_sender));
                out.push(u8::from(r.is_responder));
                out.extend_from_slice(&r.version.to_le_bytes());
                out.extend_from_slice(&r.salt.to_le_bytes());
            }
            Self::ReqRecon(sk) | Self::Sketch(sk) => {
                write_var_bytes(&mut out, sk);
            }
            Self::ReconcilDiff {
                ask_parents,
                short_ids,
            } => {
                out.extend_from_slice(&ask_parents.to_le_bytes());
                write_compact_size(&mut out, short_ids.len() as u64);
                for id in short_ids {
                    out.extend_from_slice(&id.to_le_bytes());
                }
            }
        }
        out
    }

    /// Decodes a payload for `command`. Unknown commands produce
    /// [`Message::Unknown`]; known commands must parse completely or the
    /// message is a [`PayloadError`].
    ///
    /// # Errors
    ///
    /// [`PayloadError`] on any malformed or truncated known-command payload.
    pub fn decode(command: &Command, payload: &[u8]) -> Result<Self, PayloadError> {
        let name = command.name();
        let mut d = Decoder::new(payload);
        let msg = match name {
            "version" => {
                let version = d.read_i32_le().map_err(|e| payload_err(name, e))?;
                let services = d.read_u64_le().map_err(|e| payload_err(name, e))?;
                let timestamp = d.read_i64_le().map_err(|e| payload_err(name, e))?;
                let addr_recv = get_net_addr(&mut d, name)?;
                let addr_from = get_net_addr(&mut d, name)?;
                let nonce = d.read_u64_le().map_err(|e| payload_err(name, e))?;
                let agent_bytes = d.read_var_bytes().map_err(|e| payload_err(name, e))?;
                let start_height = d.read_i32_le().map_err(|e| payload_err(name, e))?;
                // `relay` is optional: absent on pre-BIP37 peers.
                let relay = if d.remaining() > 0 {
                    d.read_u8().map_err(|e| payload_err(name, e))? != 0
                } else {
                    true
                };
                Self::Version(Version {
                    version,
                    services,
                    timestamp,
                    addr_recv,
                    addr_from,
                    nonce,
                    user_agent: String::from_utf8_lossy(&agent_bytes).into_owned(),
                    start_height,
                    relay,
                })
            }
            "verack" => Self::Verack,
            "ping" => Self::Ping(d.read_u64_le().map_err(|e| payload_err(name, e))?),
            "pong" => Self::Pong(d.read_u64_le().map_err(|e| payload_err(name, e))?),
            "sendheaders" => Self::SendHeaders,
            "wtxidrelay" => Self::WtxidRelay,
            "sendaddrv2" => Self::SendAddrV2,
            "getaddr" => Self::GetAddr,
            "mempool" => Self::Mempool,
            "feefilter" => Self::FeeFilter(d.read_u64_le().map_err(|e| payload_err(name, e))?),
            "addr" => {
                let count = d.read_compact_size().map_err(|e| payload_err(name, e))?;
                if count > MAX_INV_SZ * 20 {
                    return Err(payload_err(
                        name,
                        format!("addr count {count} exceeds bound"),
                    ));
                }
                let mut v = Vec::with_capacity(d.bounded_capacity(count, 30));
                for _ in 0..count {
                    let time = d.read_u32_le().map_err(|e| payload_err(name, e))?;
                    let addr = get_net_addr(&mut d, name)?;
                    v.push(AddrEntry { time, addr });
                }
                Self::Addr(v)
            }
            "addrv2" => {
                let count = d.read_compact_size().map_err(|e| payload_err(name, e))?;
                if count > MAX_INV_SZ * 20 {
                    return Err(payload_err(
                        name,
                        format!("addrv2 count {count} exceeds bound"),
                    ));
                }
                let mut v = Vec::with_capacity(d.bounded_capacity(count, 8));
                for _ in 0..count {
                    let time = d.read_u32_le().map_err(|e| payload_err(name, e))?;
                    let services = d.read_compact_size().map_err(|e| payload_err(name, e))?;
                    let network = d.read_u8().map_err(|e| payload_err(name, e))?;
                    let addr_len = d.read_u8().map_err(|e| payload_err(name, e))?;
                    let addr = d
                        .read_bytes(usize::from(addr_len))
                        .map_err(|e| payload_err(name, e))?
                        .to_vec();
                    let port =
                        u16::from_be_bytes(d.read_array::<2>().map_err(|e| payload_err(name, e))?);
                    v.push(AddrV2Entry {
                        time,
                        services,
                        network,
                        addr,
                        port,
                    });
                }
                Self::AddrV2(v)
            }
            "inv" => Self::Inv(get_inv_list(&mut d, name)?),
            "getdata" => Self::GetData(get_inv_list(&mut d, name)?),
            "notfound" => Self::NotFound(get_inv_list(&mut d, name)?),
            "getheaders" => {
                let _version = d.read_u32_le().map_err(|e| payload_err(name, e))?;
                let count = d.read_compact_size().map_err(|e| payload_err(name, e))?;
                // A locator longer than the block index is meaningless.
                if count > 101 {
                    return Err(payload_err(
                        name,
                        format!("locator count {count} exceeds bound"),
                    ));
                }
                let mut locator = Vec::with_capacity(d.bounded_capacity(count, 32));
                for _ in 0..count {
                    locator.push(BlockHash::from_bytes(
                        d.read_array::<32>().map_err(|e| payload_err(name, e))?,
                    ));
                }
                let stop =
                    BlockHash::from_bytes(d.read_array::<32>().map_err(|e| payload_err(name, e))?);
                Self::GetHeaders(GetHeaders { locator, stop })
            }
            "getcfilters" | "getcfheaders" => {
                let filter_type = d.read_u8().map_err(|e| payload_err(name, e))?;
                let start_height = d.read_u32_le().map_err(|e| payload_err(name, e))?;
                let stop_hash =
                    BlockHash::from_bytes(d.read_array::<32>().map_err(|e| payload_err(name, e))?);
                let range = CFRange {
                    filter_type,
                    start_height,
                    stop_hash,
                };
                if name == "getcfilters" {
                    Self::GetCFilters(range)
                } else {
                    Self::GetCFHeaders(range)
                }
            }
            "getcfcheckpt" => {
                let filter_type = d.read_u8().map_err(|e| payload_err(name, e))?;
                let stop_hash =
                    BlockHash::from_bytes(d.read_array::<32>().map_err(|e| payload_err(name, e))?);
                Self::GetCFCheckpt(CFCheckptReq {
                    filter_type,
                    stop_hash,
                })
            }
            "cfilter" => {
                let filter_type = d.read_u8().map_err(|e| payload_err(name, e))?;
                let block_hash =
                    BlockHash::from_bytes(d.read_array::<32>().map_err(|e| payload_err(name, e))?);
                let filter = d.read_var_bytes().map_err(|e| payload_err(name, e))?;
                Self::CFilter(CFilter {
                    filter_type,
                    block_hash,
                    filter,
                })
            }
            "cfheaders" | "cfcheckpt" => {
                let filter_type = d.read_u8().map_err(|e| payload_err(name, e))?;
                let stop_hash =
                    BlockHash::from_bytes(d.read_array::<32>().map_err(|e| payload_err(name, e))?);
                if name == "cfheaders" {
                    let prev = d.read_array::<32>().map_err(|e| payload_err(name, e))?;
                    let count = d.read_compact_size().map_err(|e| payload_err(name, e))?;
                    if count > MAX_HEADERS_RESULTS {
                        return Err(payload_err(
                            name,
                            format!("cfheaders count {count} exceeds MAX_HEADERS_RESULTS"),
                        ));
                    }
                    let mut filter_hashes = Vec::with_capacity(d.bounded_capacity(count, 32));
                    for _ in 0..count {
                        filter_hashes.push(d.read_array::<32>().map_err(|e| payload_err(name, e))?);
                    }
                    Self::CFHeaders(CFHeaders {
                        filter_type,
                        stop_hash,
                        prev_filter_header: prev,
                        filter_hashes,
                    })
                } else {
                    let count = d.read_compact_size().map_err(|e| payload_err(name, e))?;
                    if count > MAX_HEADERS_RESULTS {
                        return Err(payload_err(
                            name,
                            format!("cfcheckpt count {count} exceeds MAX_HEADERS_RESULTS"),
                        ));
                    }
                    let mut filter_headers = Vec::with_capacity(d.bounded_capacity(count, 32));
                    for _ in 0..count {
                        filter_headers
                            .push(d.read_array::<32>().map_err(|e| payload_err(name, e))?);
                    }
                    Self::CFCheckpt(CFCheckpt {
                        filter_type,
                        stop_hash,
                        filter_headers,
                    })
                }
            }
            "headers" => {
                let count = d.read_compact_size().map_err(|e| payload_err(name, e))?;
                if count > MAX_HEADERS_RESULTS {
                    return Err(payload_err(
                        name,
                        format!("headers count {count} exceeds MAX_HEADERS_RESULTS"),
                    ));
                }
                let mut headers = Vec::with_capacity(d.bounded_capacity(count, 81));
                for _ in 0..count {
                    let header = BlockHeader::read(&mut d).map_err(|e| payload_err(name, e))?;
                    let tx_count = d.read_u8().map_err(|e| payload_err(name, e))?;
                    if tx_count != 0 {
                        return Err(payload_err(
                            name,
                            "headers entry carries a nonzero tx count",
                        ));
                    }
                    headers.push(header);
                }
                Self::Headers(headers)
            }
            "block" => Self::Block(Block::read(&mut d).map_err(|e| payload_err(name, e))?),
            "tx" => Self::Tx(Transaction::read(&mut d).map_err(|e| payload_err(name, e))?),
            "reject" => {
                let message = d.read_var_bytes().map_err(|e| payload_err(name, e))?;
                let code = d.read_u8().map_err(|e| payload_err(name, e))?;
                let reason = d.read_var_bytes().map_err(|e| payload_err(name, e))?;
                let data = d
                    .read_bytes(d.remaining())
                    .map_err(|e| payload_err(name, e))?;
                Self::Reject(Reject {
                    message: String::from_utf8_lossy(&message).into_owned(),
                    code,
                    reason: String::from_utf8_lossy(&reason).into_owned(),
                    data: data.to_vec(),
                })
            }
            "sendrecon" => Self::SendRecon(SendRecon {
                is_sender: d.read_u8().map_err(|e| payload_err(name, e))? != 0,
                is_responder: d.read_u8().map_err(|e| payload_err(name, e))? != 0,
                version: d.read_u32_le().map_err(|e| payload_err(name, e))?,
                salt: d.read_u64_le().map_err(|e| payload_err(name, e))?,
            }),
            "reqrecon" | "sketch" => {
                let sk = d.read_var_bytes().map_err(|e| payload_err(name, e))?;
                if sk.len() > MAX_SKETCH_BYTES {
                    return Err(payload_err(name, "sketch exceeds capacity bound"));
                }
                if name == "reqrecon" {
                    Self::ReqRecon(sk)
                } else {
                    Self::Sketch(sk)
                }
            }
            "reconcildiff" => {
                let ask_parents = d.read_u32_le().map_err(|e| payload_err(name, e))?;
                let count = d.read_compact_size().map_err(|e| payload_err(name, e))?;
                if count > MAX_RECONCIL_IDS {
                    return Err(payload_err(name, "reconcildiff count too large"));
                }
                let mut short_ids = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    short_ids.push(d.read_u32_le().map_err(|e| payload_err(name, e))?);
                }
                Self::ReconcilDiff {
                    ask_parents,
                    short_ids,
                }
            }
            "reqbisec" => Self::ReqBisec,
            _ => {
                return Ok(Self::Unknown {
                    command: name.to_string(),
                    payload: payload.to_vec(),
                });
            }
        };
        d.finish().map_err(|e| payload_err(name, e))?;
        Ok(msg)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use avila_consensus::hex;

    const GENESIS_HEADER_HEX: &str = "0100000000000000000000000000000000000000000000000000000000000000\
000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    fn genesis_header() -> BlockHeader {
        BlockHeader::decode(&hex::decode(GENESIS_HEADER_HEX).unwrap()).unwrap()
    }

    fn cmd(name: &str) -> Command {
        Command::new(name).unwrap()
    }

    /// Encode → decode round trip.
    fn round_trip(msg: &Message) -> Message {
        let payload = msg.encode();
        Message::decode(&cmd(msg.command_name()), &payload).unwrap()
    }

    fn version_msg() -> Message {
        Message::Version(Version {
            version: PROTOCOL_VERSION,
            services: NODE_NETWORK | NODE_WITNESS,
            timestamp: 1_800_000_000,
            addr_recv: NetAddr::unspecified(),
            addr_from: NetAddr {
                services: NODE_NETWORK,
                ip: [0; 16],
                port: 8333,
            },
            nonce: 0xdead_beef,
            user_agent: "/Avila:0.1.0/".to_string(),
            start_height: 500,
            relay: true,
        })
    }

    #[test]
    fn version_round_trip() {
        assert_eq!(round_trip(&version_msg()), version_msg());
    }

    #[test]
    fn version_without_relay_byte_decodes() {
        // Pre-BIP37 peers omit `relay` — the payload ends at start_height.
        let mut payload = version_msg().encode();
        payload.pop();
        match Message::decode(&cmd("version"), &payload).unwrap() {
            Message::Version(v) => {
                assert_eq!(v.start_height, 500);
                assert!(v.relay); // defaulted, per Core's receive-side convention
            }
            other => panic!("expected Version, got {other:?}"),
        }
    }

    #[test]
    fn fixed_size_messages_round_trip() {
        for msg in [
            Message::Verack,
            Message::SendHeaders,
            Message::WtxidRelay,
            Message::SendAddrV2,
            Message::GetAddr,
            Message::Mempool,
            Message::Ping(0x1234_5678),
            Message::Pong(u64::MAX),
            Message::FeeFilter(1_000),
        ] {
            assert_eq!(round_trip(&msg), msg);
        }
    }

    #[test]
    fn inv_vectors_round_trip() {
        let hash = genesis_header().hash();
        for kind in [
            InvType::Tx,
            InvType::Block,
            InvType::Wtx,
            InvType::WitnessBlock,
            InvType::WitnessTx,
            InvType::Other(0x8000_0002),
        ] {
            let inv = InvVector {
                inv_type: kind,
                hash,
            };
            for msg in [
                Message::Inv(vec![inv]),
                Message::GetData(vec![inv]),
                Message::NotFound(vec![inv]),
            ] {
                assert_eq!(round_trip(&msg), msg);
            }
        }
    }

    #[test]
    fn inv_count_is_bounded() {
        let mut payload = Vec::new();
        write_compact_size(&mut payload, MAX_INV_SZ + 1);
        assert!(Message::decode(&cmd("inv"), &payload).is_err());
    }

    #[test]
    fn getheaders_round_trip() {
        let gh = Message::GetHeaders(GetHeaders {
            locator: vec![genesis_header().hash()],
            stop: BlockHash::ZERO,
        });
        assert_eq!(round_trip(&gh), gh);
    }

    #[test]
    fn getheaders_locator_is_bounded() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        write_compact_size(&mut payload, 102); // > 101
        assert!(Message::decode(&cmd("getheaders"), &payload).is_err());
    }

    #[test]
    fn headers_round_trip() {
        let mut h2 = genesis_header();
        h2.prev_block_hash = genesis_header().hash();
        h2.nonce = 42;
        let msg = Message::Headers(vec![genesis_header(), h2]);
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn headers_over_2000_is_rejected() {
        let mut payload = Vec::new();
        write_compact_size(&mut payload, MAX_HEADERS_RESULTS + 1);
        assert!(Message::decode(&cmd("headers"), &payload).is_err());
    }

    #[test]
    fn headers_with_tx_count_is_rejected() {
        // The BIP152-style encoding requires a zero tx count per header; a
        // nonzero count means the peer is sending us something else.
        let mut payload = Vec::new();
        write_compact_size(&mut payload, 1);
        payload.extend_from_slice(&genesis_header().encode());
        payload.push(1);
        let err = Message::decode(&cmd("headers"), &payload).unwrap_err();
        assert!(err.detail.contains("nonzero tx count"));
    }

    #[test]
    fn headers_empty_is_valid() {
        let msg = Message::Headers(vec![]);
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn block_and_tx_use_consensus_codecs() {
        // The block payload must equal Block::encode byte-for-byte — the
        // wire format is the consensus format.
        let coinbase = Transaction {
            version: 1,
            inputs: vec![avila_consensus::transaction::TxIn {
                previous_output: avila_consensus::transaction::OutPoint::NULL,
                script_sig: avila_consensus::transaction::Script::new(vec![0x51]),
                sequence: 0xffff_ffff,
                witness: avila_consensus::transaction::Witness::default(),
            }],
            outputs: vec![avila_consensus::transaction::TxOut {
                value: 5_000_000_000,
                script_pubkey: avila_consensus::transaction::Script::new(vec![0x51]),
            }],
            lock_time: 0,
        };
        let mut block = Block {
            header: genesis_header(),
            transactions: vec![coinbase],
        };
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        let msg = Message::Block(block.clone());
        assert_eq!(msg.encode(), block.encode());
        assert_eq!(round_trip(&msg), msg);
        let tx_msg = Message::Tx(block.transactions[0].clone());
        assert_eq!(tx_msg.encode(), block.transactions[0].encode());
        assert_eq!(round_trip(&tx_msg), tx_msg);
    }

    #[test]
    fn addr_round_trip() {
        let entry = AddrEntry {
            time: 1_700_000_000,
            addr: NetAddr {
                services: NODE_NETWORK | NODE_NETWORK_LIMITED,
                ip: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4],
                port: 8333,
            },
        };
        let msg = Message::Addr(vec![entry]);
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn addrv2_round_trip_including_onion() {
        let ipv4 = AddrV2Entry {
            time: 1_700_000_000,
            services: NODE_NETWORK,
            network: 1,
            addr: vec![9, 9, 9, 9],
            port: 8333,
        };
        let torv3 = AddrV2Entry {
            time: 1_700_000_000,
            services: 0,
            network: 4,
            addr: vec![0x77; 32],
            port: 8333,
        };
        let msg = Message::AddrV2(vec![ipv4, torv3]);
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn reject_round_trip() {
        let msg = Message::Reject(Reject {
            message: "block".to_string(),
            code: 0x10,
            reason: "bad-version".to_string(),
            data: vec![0xaa; 32],
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn unknown_command_preserves_payload() {
        let payload = b"\x01\x02\x03".to_vec();
        let msg = Message::decode(&cmd("mystery"), &payload).unwrap();
        assert_eq!(
            msg,
            Message::Unknown {
                command: "mystery".to_string(),
                payload
            }
        );
    }

    #[test]
    fn truncated_payloads_error() {
        // Every known command must fail cleanly on a cut payload — never panic.
        for name in [
            "version",
            "ping",
            "feefilter",
            "addr",
            "addrv2",
            "inv",
            "getdata",
            "getheaders",
            "headers",
            "block",
            "tx",
            "reject",
        ] {
            let wire = Message::decode(&cmd(name), &[]);
            assert!(
                wire.is_err() || matches!(wire, Ok(Message::Unknown { .. })),
                "{name}"
            );
        }
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut payload = Message::Verack.encode();
        payload.push(0xee);
        assert!(Message::decode(&cmd("verack"), &payload).is_err());
    }
}

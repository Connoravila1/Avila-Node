//! A minimal JSON-RPC 1.0 query surface for the running node —
//! Core's `-rpcport` analog, scoped to *read-only* observations.
//!
//! Two data sources, both strictly local:
//!
//! * the last-published [`SyncProgress`] snapshot (chain/sync/mempool
//!   status), and
//! * the live [`Chainstate`]/[`PeerManager`] via [`ChainQuery`] — a
//!   message the sync loop answers between ticks, so queries read
//!   validated state without locking the sync path (the role Core's
//!   `cs_main` critical section plays for its RPC thread).
//!
//! There is no wallet; the mutation methods are `sendrawtransaction`
//! (pool admission + peer relay), `submitblock`/`submitheader`
//! (chainstate connect + tip announce), `generatetoaddress`/
//! `generateblock` (template → grind → connect → announce), and the
//! `stop` control method (the same cancellation flag a GUI Stop
//! button or SIGINT handler flips). Every answer is "what this node
//! has itself observed", never a remote claim.
//!
//! Not implemented (by design, this slice): HTTP keep-alive, chunked
//! encoding, TLS, authentication beyond localhost binding, batch
//! requests, and the wallet method surface.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use avila_consensus::address::{script_address, validate_address};
use avila_consensus::arith::difficulty_from_compact;
use avila_consensus::chain::HeaderNode;
use avila_consensus::chainstate::Chainstate;
use avila_consensus::check::RuleError;
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::header::BlockHeader;
use avila_consensus::hex;
use avila_consensus::transaction::{OutPoint, Script, Transaction};
use avila_p2p::manager::PeerManager;
use serde_json::{Value, json};

use crate::sync::SyncProgress;

/// The shared snapshot the sync loop publishes and the RPC server reads.
pub type SharedStatus = Arc<RwLock<SyncProgress>>;

/// The query body: act on live state, produce a JSON result or a
/// JSON-RPC `(code, message)` error. `&mut` receivers let mutation
/// methods (`sendrawtransaction`, `submitblock`) reach the mempool,
/// the chainstate, and relay.
type QueryFn = Box<
    dyn FnOnce(&mut Chainstate, &mut PeerManager<TcpStream>) -> Result<Value, (i64, String)> + Send,
>;

/// A query the sync loop answers against the live chainstate
/// and peer manager between ticks. The reply carries either the JSON
/// result or a JSON-RPC `(code, message)` error.
pub struct ChainQuery {
    run: QueryFn,
    reply: mpsc::Sender<Result<Value, (i64, String)>>,
}

impl ChainQuery {
    /// Executes the query against the live node state and delivers the
    /// answer. Called by the sync loop; a dropped receiver just means the
    /// caller gave up waiting.
    pub fn answer(self, cs: &mut Chainstate, mgr: &mut PeerManager<TcpStream>) {
        let _ = self.reply.send((self.run)(cs, mgr));
    }
}

/// The sending half of the chain-query channel — the RPC server holds
/// one, the sync loop holds the receiving half.
pub type QuerySender = mpsc::Sender<ChainQuery>;

/// Request/response byte cap — RPC requests are small; a peer that
/// floods headers past this is disconnected.
const MAX_REQUEST: usize = 64 * 1024;

/// How long a chain query may wait for the sync loop to answer.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Spawns the RPC listener on its own thread. `status` is read per
/// request — answers reflect the most recent sync tick, not a live
/// call into the validator. `queries`, when present, reaches the live
/// chainstate through the sync loop for chain data methods. `stop`,
/// when present, is the flag the sync loop's cancellation check reads —
/// the `stop` method sets it. `auth`, when present, is the expected
/// `Authorization` header value (Core's cookie auth: HTTP Basic with
/// user `__cookie__`).
///
/// # Errors
/// `io::Error` if the listener cannot bind.
pub fn serve(
    addr: SocketAddr,
    status: SharedStatus,
    queries: Option<QuerySender>,
    waiters: Option<Arc<BlockWaiters>>,
    stop: Option<Arc<AtomicBool>>,
    auth: Option<String>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)?;
    Ok(thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let status = status.clone();
                    let queries = queries.clone();
                    let waiters = waiters.clone();
                    let stop = stop.clone();
                    let auth = auth.clone();
                    thread::spawn(move || {
                        handle(
                            stream,
                            &status,
                            queries.as_ref(),
                            waiters.as_ref(),
                            stop.as_ref(),
                            auth.as_deref(),
                        );
                    });
                }
                Err(_) => continue,
            }
        }
    }))
}

/// Minimal base64 encoding (RFC 4648, no padding omissions) — enough
/// for HTTP Basic credentials without taking a dependency.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// Core's strict `DecodeBase64` — alphabet bytes and `=` padding only
/// at the tail, no whitespace, length a multiple of 4. `None` on any
/// violation, which `verifymessage` maps to "Malformed base64
/// encoding".
fn base64_decode_strict(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    fn digit(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a' + 26)),
            b'0'..=b'9' => Some(u32::from(c - b'0' + 52)),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for (i, chunk) in text.as_bytes().chunks(4).enumerate() {
        let last = (i + 1) * 4 == text.len();
        let data_len = chunk.iter().take_while(|&&c| c != b'=').count();
        // `=` may only pad the final chunk, at most twice, and only at
        // the tail of the chunk itself.
        if !chunk[data_len..].iter().all(|&c| c == b'=') {
            return None;
        }
        let pad = 4 - data_len;
        if pad > 0 && (!last || pad > 2) {
            return None;
        }
        let (d0, d1) = (digit(chunk[0])?, digit(chunk[1])?);
        let d2 = if pad >= 2 { 0 } else { digit(chunk[2])? };
        let d3 = if pad >= 1 { 0 } else { digit(chunk[3])? };
        let n = (d0 << 18) | (d1 << 12) | (d2 << 6) | d3;
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// The `Authorization` header value Core-compatible clients send for a
/// cookie token: `Basic base64("__cookie__:<token>")`.
#[must_use]
pub fn cookie_auth_header(token: &str) -> String {
    format!(
        "Basic {}",
        base64_encode(format!("__cookie__:{token}").as_bytes())
    )
}

/// Constant-time-ish comparison for credential values (byte fold, no
/// early exit on the value bytes themselves).
fn credentials_match(got: &str, expected: &str) -> bool {
    let (a, b) = (got.as_bytes(), expected.as_bytes());
    let mut diff = a.len() ^ b.len();
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= usize::from(x ^ y);
    }
    diff == 0
}

/// The cookie file's filename inside the network data directory —
/// Core's `.cookie` convention, same `__cookie__:<token>` contents.
pub const COOKIE_FILE: &str = ".cookie";

/// Writes a fresh cookie token into `dir` (Core regenerates per run)
/// with owner-only permissions, returning the token.
///
/// # Errors
/// `io::Error` if the file cannot be created or written.
pub fn write_cookie(dir: &std::path::Path) -> std::io::Result<String> {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy)
        .map_err(|e| std::io::Error::other(format!("entropy source: {e}")))?;
    let token = hex::encode(&entropy);
    let path = dir.join(COOKIE_FILE);
    std::fs::write(&path, format!("__cookie__:{token}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(token)
}

/// Reads the cookie token from `dir`'s `.cookie` file.
///
/// # Errors
/// `io::Error` if the file is missing or malformed.
pub fn read_cookie(dir: &std::path::Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(dir.join(COOKIE_FILE))?;
    text.trim()
        .strip_prefix("__cookie__:")
        .map(str::to_string)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed .cookie file")
        })
}

/// Response-body cap — a verbosity-0 `getblock` of a maximal block is
/// ~8 MB of hex; anything past this is a misbehaving server.
const MAX_RESPONSE: u64 = 32 * 1024 * 1024;

/// A blocking JSON-RPC call — the transport behind the `rpc`
/// subcommand and, later, the GUI's daemon-attach path. `auth` is the
/// full `Authorization` header value ([`cookie_auth_header`]).
///
/// # Errors
/// A `String` describing the transport, HTTP, or JSON failure.
pub fn call(addr: SocketAddr, auth: Option<&str>, request: &Value) -> Result<Value, String> {
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(|e| e.to_string())?;
    let body = request.to_string();
    let mut head = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(value) = auth {
        head.push_str("Authorization: ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body.as_bytes()))
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    stream
        .take(MAX_RESPONSE)
        .read_to_end(&mut buf)
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&buf);
    let Some(boundary) = text.find("\r\n\r\n") else {
        return Err("malformed HTTP response".into());
    };
    let status_line = text[..boundary].lines().next().unwrap_or_default();
    if !status_line.contains(" 200") {
        return Err(if status_line.contains("401") {
            "unauthorized — bad or missing cookie credentials".into()
        } else {
            format!("HTTP {status_line}")
        });
    }
    serde_json::from_str(text[boundary + 4..].trim())
        .map_err(|e| format!("invalid JSON-RPC response: {e}"))
}

/// JSON-RPC error codes Core uses.
const RPC_MISC_ERROR: i64 = -1;
const RPC_TYPE_ERROR: i64 = -3;
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;
const RPC_INVALID_PARAMETER: i64 = -8;
const RPC_DESERIALIZATION_ERROR: i64 = -22;
const RPC_VERIFY_ERROR: i64 = -25;
const RPC_VERIFY_REJECTED: i64 = -26;
const RPC_METHOD_NOT_FOUND: i64 = -32601;
const RPC_INVALID_PARAMS: i64 = -32602;
const RPC_INTERNAL_ERROR: i64 = -32603;
const RPC_CLIENT_NODE_ALREADY_ADDED: i64 = -23;
const RPC_CLIENT_NODE_NOT_ADDED: i64 = -24;
const RPC_CLIENT_NODE_NOT_CONNECTED: i64 = -29;
const RPC_CLIENT_INVALID_IP_OR_SUBNET: i64 = -30;

/// Core's `DEFAULT_MAX_RAW_TX_FEE_RATE` — `sendrawtransaction` refuses
/// txs paying more than this unless the caller raises it (BTC/kvB).
const DEFAULT_MAX_RAW_TX_FEE_RATE: f64 = 0.10;

fn handle(
    mut stream: TcpStream,
    status: &SharedStatus,
    queries: Option<&QuerySender>,
    waiters: Option<&Arc<BlockWaiters>>,
    stop: Option<&Arc<AtomicBool>>,
    auth: Option<&str>,
) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    // Read headers until the blank line, bounded.
    let mut content_length = 0usize;
    let mut read_bytes = 0usize;
    let mut authorization = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                read_bytes += n;
                if read_bytes > MAX_REQUEST {
                    return;
                }
                let trimmed = line.trim_end();
                let lower = trimmed.to_lowercase();
                if let Some(rest) = lower.strip_prefix("content-length:") {
                    content_length = rest.trim().parse().unwrap_or(0);
                }
                if let Some(rest) = lower.strip_prefix("authorization:") {
                    // `rest` is a suffix of `trimmed` — same length, so
                    // this slice keeps the credential's original case;
                    // trim drops the space after the colon.
                    authorization = trimmed[trimmed.len() - rest.len()..].trim().to_string();
                }
                if trimmed.is_empty() {
                    break;
                }
            }
        }
    }
    // Cookie auth — Core's default. A missing/wrong credential gets the
    // same 401 bitcoind returns, no method is reachable without it.
    if let Some(expected) = auth
        && !credentials_match(&authorization, expected)
    {
        let _ = write!(
            stream,
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"avila jsonrpc\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        let _ = stream.flush();
        return;
    }
    if content_length == 0 || content_length > MAX_REQUEST {
        return;
    }
    let mut body = vec![0u8; content_length];
    if reader.read_exact(&mut body).is_err() {
        return;
    }
    let request: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => return,
    };
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(Value::Null);
    let id = request.get("id").cloned().unwrap_or(Value::Null);

    let snap = match status.read() {
        Ok(s) => s.clone(),
        Err(_) => return,
    };
    let (result, error) = dispatch(method, &params, &snap, queries, waiters, stop);
    let response = match error {
        Some((code, message)) => {
            json!({"result": null, "error": {"code": code, "message": message}, "id": id})
        }
        None => json!({"result": result, "error": null, "id": id}),
    };
    let body = response.to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.flush();
}

/// Runs `f` against the live chainstate through the query channel and
/// shapes the outcome as `dispatch`'s `(result, error)` pair.
fn chain_query(
    queries: Option<&QuerySender>,
    f: impl FnOnce(&mut Chainstate, &mut PeerManager<TcpStream>) -> Result<Value, (i64, String)>
    + Send
    + 'static,
) -> (Value, Option<(i64, String)>) {
    let Some(tx) = queries else {
        return (
            Value::Null,
            Some((
                RPC_MISC_ERROR,
                "chain queries unavailable — the sync loop is not running".into(),
            )),
        );
    };
    let (reply_tx, reply_rx) = mpsc::channel();
    if tx
        .send(ChainQuery {
            run: Box::new(f),
            reply: reply_tx,
        })
        .is_err()
    {
        return (
            Value::Null,
            Some((RPC_MISC_ERROR, "the sync loop has stopped".into())),
        );
    }
    match reply_rx.recv_timeout(QUERY_TIMEOUT) {
        Ok(Ok(value)) => (value, None),
        Ok(Err(err)) => (Value::Null, Some(err)),
        Err(_) => (
            Value::Null,
            Some((RPC_MISC_ERROR, "chain query timed out".into())),
        ),
    }
}

/// The cap on parked `waitforblock*` predicates — a flood of wait calls
/// must not grow waiter state without bound.
const MAX_BLOCK_WAITERS: usize = 256;

/// A `waitforblock*` predicate parked by an RPC handler. The sync loop
/// re-evaluates `check` against the live chainstate each tick and
/// wakes the handler on the first hit — Core's validation-interface
/// block notifications, by polling instead of callbacks.
struct BlockWaiter {
    check: Box<dyn Fn(&Chainstate) -> bool + Send>,
    wake: mpsc::SyncSender<()>,
}

/// The waiter registry shared between the sync loop and RPC handlers.
/// The loop calls [`BlockWaiters::notify`] once per tick and
/// [`BlockWaiters::shutdown`] on the way out; handlers only register
/// and block on their own receiver, so a blocked `waitforblock` call
/// never stalls the query channel or the sync loop.
pub struct BlockWaiters {
    pending: Mutex<Vec<BlockWaiter>>,
    shutdown: AtomicBool,
}

impl BlockWaiters {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Parks `check` for per-tick evaluation; `wake` fires once it
    /// holds. Returns false when the registry is at capacity or the
    /// loop already shut down — the caller then answers the
    /// timeout-shaped result immediately rather than queueing more
    /// waiter state.
    fn register(
        &self,
        check: Box<dyn Fn(&Chainstate) -> bool + Send>,
        wake: mpsc::SyncSender<()>,
    ) -> bool {
        if self.shutdown.load(Ordering::Relaxed) {
            return false;
        }
        match self.pending.lock() {
            Ok(mut pending) if pending.len() < MAX_BLOCK_WAITERS => {
                pending.push(BlockWaiter { check, wake });
                true
            }
            _ => false,
        }
    }

    /// Sync-loop hook, once per tick: fires and drops every waiter
    /// whose predicate now holds against the live chainstate.
    pub fn notify(&self, cs: &Chainstate) {
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        pending.retain(|w| {
            if (w.check)(cs) {
                let _ = w.wake.try_send(());
                false
            } else {
                true
            }
        });
    }

    /// Sync-loop exit: wakes every parked waiter so handlers answer
    /// with the last tip instead of hanging on a dead channel — the
    /// role Core's shutdown interrupt plays for its wait calls.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Ok(mut pending) = self.pending.lock() {
            for w in pending.drain(..) {
                let _ = w.wake.try_send(());
            }
        }
    }

    /// Whether [`BlockWaiters::shutdown`] already ran — woken handlers
    /// then answer the registration snapshot instead of querying a
    /// stopped loop.
    fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }
}

impl Default for BlockWaiters {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for BlockWaiters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockWaiters")
            .field(
                "pending",
                &self.pending.lock().map(|p| p.len()).unwrap_or(usize::MAX),
            )
            .field("shutdown", &self.is_shutdown())
            .finish()
    }
}

/// The `{hash, height}` answer all three wait calls produce — the
/// connected tip at the moment the wait ends, not the target.
fn wait_tip_result(cs: &Chainstate) -> Value {
    json!({
        "hash": cs.chain().last().map(ToString::to_string).unwrap_or_default(),
        "height": cs.chain().len().saturating_sub(1) as u64,
    })
}

/// The shared `timeout` argument of the `waitforblock*` family: null
/// or missing → 0 (wait forever), non-integral → Core's integer-range
/// error, negative → its `Negative timeout` error.
fn wait_timeout_ms(v: Option<&Value>) -> Result<i64, (i64, String)> {
    let Some(v) = v.filter(|v| !v.is_null()) else {
        return Ok(0);
    };
    let Some(ms) = v.as_i64() else {
        return Err((RPC_MISC_ERROR, "JSON integer out of range".into()));
    };
    if ms < 0 {
        return Err((RPC_MISC_ERROR, "Negative timeout".into()));
    }
    Ok(ms)
}

/// The `waitforblock*` engine: registers `check` with the sync loop's
/// waiter registry — predicate-check and registration ride the same
/// chain query so a block landing between them can't be missed — then
/// blocks this connection's thread until it fires, the deadline
/// passes, or the loop shuts down. The answer is always the live tip
/// (Core returns the current block on timeout or exit).
fn block_wait(
    queries: Option<&QuerySender>,
    waiters: Option<&Arc<BlockWaiters>>,
    timeout_ms: i64,
    check: impl Fn(&Chainstate) -> bool + Send + 'static,
) -> (Value, Option<(i64, String)>) {
    let Some(waiters) = waiters else {
        // No sync loop is feeding waiters — answer the current tip,
        // the same shape a zero-length timeout returns.
        return chain_query(queries, |cs, _| Ok(wait_tip_result(cs)));
    };
    let (wake_tx, wake_rx) = mpsc::sync_channel(1);
    let registry = Arc::clone(waiters);
    let (reg, reg_err) = chain_query(queries, move |cs, _| {
        let satisfied = check(cs) || !registry.register(Box::new(check), wake_tx);
        Ok(json!({"tip": wait_tip_result(cs), "waiting": !satisfied}))
    });
    if let Some(err) = reg_err {
        return (Value::Null, Some(err));
    }
    let start_tip = reg.get("tip").cloned().unwrap_or(Value::Null);
    if !reg.get("waiting").and_then(Value::as_bool).unwrap_or(false) {
        return (start_tip, None);
    }
    match (timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(timeout_ms as u64)) {
        Some(deadline) => {
            if let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                // Fired, timed out, or the registry went away — every
                // outcome ends the wait.
                let _ = wake_rx.recv_timeout(remaining);
            }
        }
        None => {
            let _ = wake_rx.recv();
        }
    }
    // The loop is gone — answer the snapshot taken at registration.
    if waiters.is_shutdown() {
        return (start_tip, None);
    }
    let (tip, err) = chain_query(queries, |cs, _| Ok(wait_tip_result(cs)));
    if tip.is_null() {
        (start_tip, None)
    } else {
        (tip, err)
    }
}

/// The `UniValue` type name Core's `Wrong type passed` errors use.
fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn param<'a>(params: &'a Value, index: usize, name: &str) -> Option<&'a Value> {
    params.get(index).or_else(|| params.get(name))
}

/// `logging`'s mutable category state — Core's `g_logger` category
/// set. The toggles are advisory: our log sites don't yet gate on
/// categories, but the RPC contract (include/exclude ordering, the
/// `all`/`1` specials, reported state) is exact.
static LOG_CATEGORIES: std::sync::Mutex<[bool; 28]> = std::sync::Mutex::new([false; 28]);

/// Core's `BCLog::LogFlags` names, in `logging`'s reported order.
const LOG_CATEGORY_NAMES: [&str; 28] = [
    "addrman",
    "bench",
    "blockstorage",
    "cmpctblock",
    "coindb",
    "estimatefee",
    "http",
    "i2p",
    "ipc",
    "leveldb",
    "libevent",
    "mempool",
    "mempoolrej",
    "net",
    "proxy",
    "prune",
    "qt",
    "rand",
    "reindex",
    "rpc",
    "scan",
    "selectcoins",
    "tor",
    "txpackages",
    "txreconciliation",
    "validation",
    "walletdb",
    "zmq",
];

/// `getmemoryinfo "mallocinfo"` — glibc's `malloc_info` needs raw FFI,
/// which the workspace's `unsafe-code` forbid rules out. `None`
/// mirrors Core's `!HAVE_MALLOC_INFO` build variant ("mallocinfo mode
/// not supported").
fn malloc_info_xml() -> Option<String> {
    None
}

/// `RPCTypeCheckArgument`'s message — the `Wrong type passed:` list
/// keyed by position and argument name.
fn wrong_type_message(position: usize, name: &str, v: &Value, expected: &str) -> String {
    wrong_type_list(&[(position, name, v, expected)])
}

/// RPCHelpMan's collected type error — every bad argument reported at
/// once, `"Position N (name)": "JSON value of type X is not of
/// expected type Y"` per line.
fn wrong_type_list(errors: &[(usize, &str, &Value, &str)]) -> String {
    let body = errors
        .iter()
        .map(|(position, name, v, expected)| {
            format!(
                "    \"Position {position} ({name})\": \"{}\"",
                field_type_message(v, expected)
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");
    format!("Wrong type passed:\n{{\n{body}\n}}")
}

/// The bare field/element type error — `RPCTypeCheckObj`/`RPCTypeCheck`
/// wording without the `Position` wrapper Core adds at top level.
fn field_type_message(v: &Value, expected: &str) -> String {
    format!(
        "JSON value of type {} is not of expected type {expected}",
        json_type_name(v)
    )
}

/// Core's `UniValue::setFloat` — `std::setprecision(16)` in the
/// default float format, i.e. C's `%.16g`: up to 16 significant
/// digits, trailing zeros stripped, scientific notation when the
/// decimal exponent is outside `[-4, 16)`. serde's ryu
/// shortest-round-trip text differs at the last digit for some
/// values (e.g. 101/17 → `5.9411764705882355` vs Core's
/// `5.941176470588236`), so doubles the reference formats through
/// `setFloat` go through this.
fn g16(v: f64) -> String {
    if !v.is_finite() {
        // A non-finite double can't be a JSON number; callers never
        // reach this for consensus-derived values.
        return "null".to_string();
    }
    if v == 0.0 {
        return if v.is_sign_negative() { "-0" } else { "0" }.to_string();
    }
    // 16 significant digits in scientific form — Rust's float
    // formatting rounds correctly to the last digit, like printf.
    let s = format!("{:.15e}", v);
    let Some((mant, exp_s)) = s.split_once('e') else {
        return "0".to_string();
    };
    let exp: i32 = exp_s.parse().unwrap_or(0);
    if !(-4..16).contains(&exp) {
        // Scientific: strip mantissa trailing zeros, exponent signed
        // and padded to two digits (C's `%g`).
        let mant = mant.trim_end_matches('0').trim_end_matches('.');
        format!("{mant}e{exp:+03}")
    } else {
        // Fixed: `15 - exp` fraction digits keeps 16 significant, then
        // strip the fractional padding %g removes — only past the
        // point, never integer digits.
        let fixed = format!("{:.*}", (15 - exp) as usize, v);
        if fixed.contains('.') {
            fixed
                .trim_end_matches('0')
                .trim_end_matches('.')
                .to_string()
        } else {
            fixed
        }
    }
}

/// A `Value` carrying `g16`'s literal text — requires serde_json's
/// `arbitrary_precision` so the digits survive re-serialization.
fn float_g16(v: f64) -> Value {
    serde_json::from_str(&g16(v)).unwrap_or(Value::Null)
}

/// Core's `ParseHashV`: 64-char hex, else -8 with its exact wording.
fn parse_hash_v<T>(s: &str, name: &str) -> Result<T, (i64, String)>
where
    T: std::str::FromStr,
{
    if s.len() != 64 {
        return Err((
            RPC_INVALID_PARAMETER,
            format!("{name} must be of length 64 (not {}, for '{s}')", s.len()),
        ));
    }
    s.parse::<T>().map_err(|_| {
        (
            RPC_INVALID_PARAMETER,
            format!("{name} must be hexadecimal string (not '{s}')"),
        )
    })
}

/// Core's `UniValue::getValStr` — the scalar string form: strings and
/// numbers return their literal text, `true` returns `"1"`, and
/// `false`, `null`, arrays and objects return `""`.
fn val_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => if *b { "1" } else { "" }.to_string(),
        _ => String::new(),
    }
}

/// Core's `ParseFixedPoint` (`util/strencodings.cpp`) — a faithful port
/// down to the overflow bound (`10^18 - 1`), the single leading zero
/// rule, optional `e`/`E` exponent, and the trailing-garbage check.
fn parse_fixed_point(val: &str, decimals: i64) -> Option<i64> {
    const UPPER_BOUND: i64 = 1_000_000_000_000_000_000 - 1;
    let b = val.as_bytes();
    let (mut ptr, end) = (0usize, b.len());
    let mut mantissa: i64 = 0;
    let mut exponent: i64 = 0;
    let mut mantissa_tzeros = 0i32;
    let (mut mantissa_sign, mut exponent_sign) = (false, false);
    let mut point_ofs = 0i64;

    fn digit(m: &mut i64, tz: &mut i32, ch: u8) -> bool {
        if ch == b'0' {
            *tz += 1;
        } else {
            for _ in 0..=*tz {
                if *m > UPPER_BOUND / 10 {
                    return false;
                }
                *m *= 10;
            }
            *m += i64::from(ch - b'0');
            *tz = 0;
        }
        true
    }

    if ptr < end && b[ptr] == b'-' {
        mantissa_sign = true;
        ptr += 1;
    }
    if ptr < end {
        if b[ptr] == b'0' {
            ptr += 1;
        } else if b[ptr].is_ascii_digit() {
            while ptr < end && b[ptr].is_ascii_digit() {
                if !digit(&mut mantissa, &mut mantissa_tzeros, b[ptr]) {
                    return None;
                }
                ptr += 1;
            }
        } else {
            return None;
        }
    } else {
        return None;
    }
    if ptr < end && b[ptr] == b'.' {
        ptr += 1;
        if ptr < end && b[ptr].is_ascii_digit() {
            while ptr < end && b[ptr].is_ascii_digit() {
                if !digit(&mut mantissa, &mut mantissa_tzeros, b[ptr]) {
                    return None;
                }
                ptr += 1;
                point_ofs += 1;
            }
        } else {
            return None;
        }
    }
    if ptr < end && (b[ptr] == b'e' || b[ptr] == b'E') {
        ptr += 1;
        if ptr < end && b[ptr] == b'+' {
            ptr += 1;
        } else if ptr < end && b[ptr] == b'-' {
            exponent_sign = true;
            ptr += 1;
        }
        if ptr < end && b[ptr].is_ascii_digit() {
            while ptr < end && b[ptr].is_ascii_digit() {
                if exponent > UPPER_BOUND / 10 {
                    return None;
                }
                exponent = exponent * 10 + i64::from(b[ptr] - b'0');
                ptr += 1;
            }
        } else {
            return None;
        }
    }
    if ptr != end {
        return None;
    }
    if exponent_sign {
        exponent = -exponent;
    }
    exponent += mantissa_tzeros as i64 - point_ofs;
    if mantissa_sign {
        mantissa = -mantissa;
    }
    exponent += decimals;
    if !(0..18).contains(&exponent) {
        return None;
    }
    for _ in 0..exponent {
        if !(-(UPPER_BOUND / 10)..=UPPER_BOUND / 10).contains(&mantissa) {
            return None;
        }
        mantissa *= 10;
    }
    if !(-UPPER_BOUND..=UPPER_BOUND).contains(&mantissa) {
        return None;
    }
    Some(mantissa)
}

/// Core's `AmountFromValue` (`rpc/util.cpp`) — a number or string run
/// through `ParseFixedPoint` at 8 decimals, then `MoneyRange`
/// (`0 <= v <= 21000000*COIN`).
fn amount_from_value(v: &Value) -> Result<i64, (i64, String)> {
    if !v.is_number() && !v.is_string() {
        return Err((RPC_TYPE_ERROR, "Amount is not a number or string".into()));
    }
    let Some(amount) = parse_fixed_point(&val_str(v), 8) else {
        return Err((RPC_TYPE_ERROR, "Invalid amount".into()));
    };
    if !(0..=21_000_000 * 100_000_000).contains(&amount) {
        return Err((RPC_TYPE_ERROR, "Amount out of range".into()));
    }
    Ok(amount)
}

/// `LookupSubNet` — parses `"a.b.c.d/n"` or `"v6::/n"` into the
/// 16-byte network plus prefix length (v4 nets become v6-mapped with
/// a +96 shift). `None` on anything unparseable.
fn parse_subnet(s: &str) -> Option<([u8; 16], u8)> {
    let (host, plen_s) = s.split_once('/')?;
    let plen: u8 = plen_s.parse().ok()?;
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        if plen > 32 {
            return None;
        }
        return Some((v4.to_ipv6_mapped().octets(), 96 + plen));
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        if plen > 128 {
            return None;
        }
        return Some((v6.octets(), plen));
    }
    None
}

/// Core's `ConnectionTypeFromValue` — the `addnode`/`addconnection`
/// connection-type vocabulary.
fn connection_type_from(s: &str) -> Option<&'static str> {
    match s {
        "inbound" => Some("inbound"),
        "manual" => Some("manual"),
        "feeler" => Some("feeler"),
        "outbound-full-relay" => Some("outbound-full-relay"),
        "block-relay-only" => Some("block-relay-only"),
        "addr-fetch" => Some("addr-fetch"),
        _ => None,
    }
}

/// Core throws the method's full `RPCHelpMan` text as a -1 error when
/// required args are absent or the arg count is out of range.
fn help_error(text: &'static str) -> (Value, Option<(i64, String)>) {
    (Value::Null, Some((RPC_MISC_ERROR, text.to_string())))
}

/// Wall-clock UNIX seconds — the ban list's timestamps live on wall
/// time (`ban_created`/`banned_until` are epoch values).
fn epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Verbatim `help decoderawtransaction` text (Bitcoin Core 29).
const DECODERAWTRANSACTION_HELP: &str = "decoderawtransaction \"hexstring\" ( iswitness )\n\nReturn a JSON object representing the serialized, hex-encoded transaction.\n\nArguments:\n1. hexstring    (string, required) The transaction hex string\n2. iswitness    (boolean, optional, default=depends on heuristic tests) Whether the transaction hex is a serialized witness transaction.\n                If iswitness is not present, heuristic tests will be used in decoding.\n                If true, only witness deserialization will be tried.\n                If false, only non-witness deserialization will be tried.\n                This boolean should reflect whether the transaction has inputs\n                (e.g. fully valid, or on-chain transactions), if known by the caller.\n\nResult:\n{                             (json object)\n  \"txid\" : \"hex\",             (string) The transaction id\n  \"hash\" : \"hex\",             (string) The transaction hash (differs from txid for witness transactions)\n  \"size\" : n,                 (numeric) The serialized transaction size\n  \"vsize\" : n,                (numeric) The virtual transaction size (differs from size for witness transactions)\n  \"weight\" : n,               (numeric) The transaction's weight (between vsize*4-3 and vsize*4)\n  \"version\" : n,              (numeric) The version\n  \"locktime\" : xxx,           (numeric) The lock time\n  \"vin\" : [                   (json array)\n    {                         (json object)\n      \"coinbase\" : \"hex\",     (string, optional) The coinbase value (only if coinbase transaction)\n      \"txid\" : \"hex\",         (string, optional) The transaction id (if not coinbase transaction)\n      \"vout\" : n,             (numeric, optional) The output number (if not coinbase transaction)\n      \"scriptSig\" : {         (json object, optional) The script (if not coinbase transaction)\n        \"asm\" : \"str\",        (string) Disassembly of the signature script\n        \"hex\" : \"hex\"         (string) The raw signature script bytes, hex-encoded\n      },\n      \"txinwitness\" : [       (json array, optional)\n        \"hex\",                (string) hex-encoded witness data (if any)\n        ...\n      ],\n      \"sequence\" : n          (numeric) The script sequence number\n    },\n    ...\n  ],\n  \"vout\" : [                  (json array)\n    {                         (json object)\n      \"value\" : n,            (numeric) The value in BTC\n      \"n\" : n,                (numeric) index\n      \"scriptPubKey\" : {      (json object)\n        \"asm\" : \"str\",        (string) Disassembly of the output script\n        \"desc\" : \"str\",       (string) Inferred descriptor for the output\n        \"hex\" : \"hex\",        (string) The raw output script bytes, hex-encoded\n        \"address\" : \"str\",    (string, optional) The Bitcoin address (only if a well-defined address exists)\n        \"type\" : \"str\"        (string) The type (one of: nonstandard, anchor, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_scripthash, witness_v0_keyhash, witness_v1_taproot, witness_unknown)\n      }\n    },\n    ...\n  ]\n}\n\nExamples:\n> bitcoin-cli decoderawtransaction \"hexstring\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"decoderawtransaction\", \"params\": [\"hexstring\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help createrawtransaction` text (Bitcoin Core 29).
const CREATERAWTRANSACTION_HELP: &str = "createrawtransaction [{\"txid\":\"hex\",\"vout\":n,\"sequence\":n},...] [{\"address\":amount,...},{\"data\":\"hex\"},...] ( locktime replaceable )\n\nCreate a transaction spending the given inputs and creating new outputs.\nOutputs can be addresses or data.\nReturns hex-encoded raw transaction.\nNote that the transaction's inputs are not signed, and\nit is not stored in the wallet or transmitted to the network.\n\nArguments:\n1. inputs                      (json array, required) The inputs\n     [\n       {                       (json object)\n         \"txid\": \"hex\",        (string, required) The transaction id\n         \"vout\": n,            (numeric, required) The output number\n         \"sequence\": n,        (numeric, optional, default=depends on the value of the 'replaceable' and 'locktime' arguments) The sequence number\n       },\n       ...\n     ]\n2. outputs                     (json array, required) The outputs specified as key-value pairs.\n                               Each key may only appear once, i.e. there can only be one 'data' output, and no address may be duplicated.\n                               At least one output of either type must be specified.\n                               For compatibility reasons, a dictionary, which holds the key-value pairs directly, is also\n                               accepted as second parameter.\n     [\n       {                       (json object)\n         \"address\": amount,    (numeric or string, required) A key-value pair. The key (string) is the bitcoin address, the value (float or string) is the amount in BTC\n         ...\n       },\n       {                       (json object)\n         \"data\": \"hex\",        (string, required) A key-value pair. The key must be \"data\", the value is hex-encoded data\n       },\n       ...\n     ]\n3. locktime                    (numeric, optional, default=0) Raw locktime. Non-0 value also locktime-activates inputs\n4. replaceable                 (boolean, optional, default=true) Marks this transaction as BIP125-replaceable.\n                               Allows this transaction to be replaced by a transaction with higher fees. If provided, it is an error if explicit sequence numbers are incompatible.\n\nResult:\n\"hex\"    (string) hex string of the transaction\n\nExamples:\n> bitcoin-cli createrawtransaction \"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"address\\\":0.01}]\"\n> bitcoin-cli createrawtransaction \"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\" \"[{\\\"data\\\":\\\"00010203\\\"}]\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"createrawtransaction\", \"params\": [\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"address\\\":0.01}]\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"createrawtransaction\", \"params\": [\"[{\\\"txid\\\":\\\"myid\\\",\\\"vout\\\":0}]\", \"[{\\\"data\\\":\\\"00010203\\\"}]\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help gettxspendingprevout` text (Bitcoin Core 29).
const GETTXSPENDINGPREVOUT_HELP: &str = "gettxspendingprevout [{\"txid\":\"hex\",\"vout\":n},...]\n\nScans the mempool to find transactions spending any of the given outputs\n\nArguments:\n1. outputs                 (json array, required) The transaction outputs that we want to check, and within each, the txid (string) vout (numeric).\n     [\n       {                   (json object)\n         \"txid\": \"hex\",    (string, required) The transaction id\n         \"vout\": n,        (numeric, required) The output number\n       },\n       ...\n     ]\n\nResult:\n[                              (json array)\n  {                            (json object)\n    \"txid\" : \"hex\",            (string) the transaction id of the checked output\n    \"vout\" : n,                (numeric) the vout value of the checked output\n    \"spendingtxid\" : \"hex\"     (string, optional) the transaction id of the mempool transaction spending this output (omitted if unspent)\n  },\n  ...\n]\n\nExamples:\n> bitcoin-cli gettxspendingprevout \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":3}]\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"gettxspendingprevout\", \"params\": [[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":3}]]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help estimatesmartfee` text (Bitcoin Core 29).
const ESTIMATESMARTFEE_HELP: &str = "estimatesmartfee conf_target ( \"estimate_mode\" )\n\nEstimates the approximate fee per kilobyte needed for a transaction to begin\nconfirmation within conf_target blocks if possible and return the number of blocks\nfor which the estimate is valid. Uses virtual transaction size as defined\nin BIP 141 (witness data is discounted).\n\nArguments:\n1. conf_target      (numeric, required) Confirmation target in blocks (1 - 1008)\n2. estimate_mode    (string, optional, default=\"economical\") The fee estimate mode.\n                    unset, economical, conservative \n                    unset means no mode set (default mode will be used). \n                    economical estimates use a shorter time horizon, making them more\n                    responsive to short-term drops in the prevailing fee market. This mode\n                    potentially returns a lower fee rate estimate.\n                    conservative estimates use a longer time horizon, making them\n                    less responsive to short-term drops in the prevailing fee market. This mode\n                    potentially returns a higher fee rate estimate.\n                    \n\nResult:\n{                   (json object)\n  \"feerate\" : n,    (numeric, optional) estimate fee rate in BTC/kvB (only present if no errors were encountered)\n  \"errors\" : [      (json array, optional) Errors encountered during processing (if there are any)\n    \"str\",          (string) error\n    ...\n  ],\n  \"blocks\" : n      (numeric) block number where estimate was found\n                    The request target will be clamped between 2 and the highest target\n                    fee estimation is able to return based on how long it has been running.\n                    An error is returned if not enough transactions and blocks\n                    have been observed to make an estimate for any number of blocks.\n}\n\nExamples:\n> bitcoin-cli estimatesmartfee 6\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"estimatesmartfee\", \"params\": [6]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getnetworkhashps` text (Bitcoin Core 29).
const GETNETWORKHASHPS_HELP: &str = "getnetworkhashps ( nblocks height )\n\nReturns the estimated network hashes per second based on the last n blocks.\nPass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\nPass in [height] to estimate the network speed at the time when a certain block was found.\n\nArguments:\n1. nblocks    (numeric, optional, default=120) The number of previous blocks to calculate estimate from, or -1 for blocks since last difficulty change.\n2. height     (numeric, optional, default=-1) To estimate at the time of the given height.\n\nResult:\nn    (numeric) Hashes per second estimated\n\nExamples:\n> bitcoin-cli getnetworkhashps \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getnetworkhashps\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getnettotals` text (Bitcoin Core 29).
const GETNETTOTALS_HELP: &str = "getnettotals\n\nReturns information about network traffic, including bytes in, bytes out,\nand current system time.\n\nResult:\n{                                              (json object)\n  \"totalbytesrecv\" : n,                        (numeric) Total bytes received\n  \"totalbytessent\" : n,                        (numeric) Total bytes sent\n  \"timemillis\" : xxx,                          (numeric) Current system UNIX epoch time in milliseconds\n  \"uploadtarget\" : {                           (json object)\n    \"timeframe\" : n,                           (numeric) Length of the measuring timeframe in seconds\n    \"target\" : n,                              (numeric) Target in bytes\n    \"target_reached\" : true|false,             (boolean) True if target is reached\n    \"serve_historical_blocks\" : true|false,    (boolean) True if serving historical blocks\n    \"bytes_left_in_cycle\" : n,                 (numeric) Bytes left in current time cycle\n    \"time_left_in_cycle\" : n                   (numeric) Seconds left in current time cycle\n  }\n}\n\nExamples:\n> bitcoin-cli getnettotals \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getnettotals\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getnodeaddresses` text (Bitcoin Core 29).
/// Verbatim `help ping` text (Bitcoin Core 29).
const PING_HELP: &str = "ping\n\nRequests that a ping be sent to all other nodes, to measure ping time.\nResults are provided in getpeerinfo.\nPing command is handled in queue with all other commands, so it measures processing backlog, not just network ping.\n\nResult:\nnull    (json null)\n\nExamples:\n> bitcoin-cli ping \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"ping\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help disconnectnode` text (Bitcoin Core 29).
const DISCONNECTNODE_HELP: &str = "disconnectnode ( \"address\" nodeid )\n\nImmediately disconnects from the specified peer node.\n\nStrictly one out of 'address' and 'nodeid' can be provided to identify the node.\n\nTo disconnect by nodeid, either set 'address' to the empty string, or call using the named 'nodeid' argument only.\n\nArguments:\n1. address    (string, optional, default=fallback to nodeid) The IP address/port of the node or subnet\n2. nodeid     (numeric, optional, default=fallback to address) The node ID (see getpeerinfo for node IDs)\n\nResult:\nnull    (json null)\n\nExamples:\n> bitcoin-cli disconnectnode \"192.168.0.6:8333\"\n> bitcoin-cli disconnectnode \"\" 1\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"disconnectnode\", \"params\": [\"192.168.0.6:8333\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"disconnectnode\", \"params\": [\"\", 1]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help addnode` text (Knots 29.3).
const ADDNODE_HELP: &str = "addnode \"node\" \"command\" ( v2transport \"connection_type\" )\n\nAttempts to add or remove a node from the addnode list.\nOr try a connection to a node once.\nAddnode connections are limited to 8 at a time and are counted separately from the -maxconnections limit.\n\nArguments:\n1. node               (string, required) The address of the peer to connect to\n2. command            (string, required) 'add' to add a node to the list, 'remove' to remove a node from the list, 'onetry' to try a connection to the node once\n3. v2transport        (boolean, optional, default=set by -v2transport) Attempt to connect using BIP324 v2 transport protocol (ignored for 'remove' command)\n4. connection_type    (string, optional, default=\"manual\") Type of connection: \n                      outbound-full-relay (default automatic connections),\n                      block-relay-only (does not relay transactions or addresses),\n                      inbound (initiated by the peer),\n                      manual (added via addnode RPC or -addnode/-connect configuration options; protected from DoS disconnection and not required to be full nodes as other outbound peers are),\n                      addr-fetch (short-lived automatic connection for soliciting addresses),\n                      feeler (short-lived automatic connection for testing addresses)\n                      Only supported for command \"onetry\" for now.\n\nResult:\nnull    (json null)\n\nExamples:\n> bitcoin-cli addnode \"192.168.0.6:8333\" \"onetry\" true\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"addnode\", \"params\": [\"192.168.0.6:8333\", \"onetry\" true]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help setnetworkactive` text (Bitcoin Core 29).
const SETNETWORKACTIVE_HELP: &str = "setnetworkactive state\n\nDisable/enable all p2p network activity.\n\nArguments:\n1. state    (boolean, required) true to enable networking, false to disable\n\nResult:\ntrue|false    (boolean) The value that was passed in\n\nExamples:\n> bitcoin-cli setnetworkactive true\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"setnetworkactive\", \"params\": [true]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getaddrmaninfo` text (Bitcoin Core 29.4).
const GETADDRMANINFO_HELP: &str = "getaddrmaninfo\n\nProvides information about the node's address manager by returning the number of addresses in the `new` and `tried` tables and their sum for all networks.\n\nResult:\n{                   (json object) json object with network type as keys\n  \"network\" : {     (json object) the network (ipv4, ipv6, onion, i2p, cjdns, all_networks)\n    \"new\" : n,      (numeric) number of addresses in the new table, which represent potential peers the node has discovered but hasn't yet successfully connected to.\n    \"tried\" : n,    (numeric) number of addresses in the tried table, which represent peers the node has successfully connected to in the past.\n    \"total\" : n     (numeric) total number of addresses in both new/tried tables\n  },\n  ...\n}\n\nExamples:\n> bitcoin-cli getaddrmaninfo \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getaddrmaninfo\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

const GETNODEADDRESSES_HELP: &str = "getnodeaddresses ( count \"network\" )\n\nReturn known addresses, after filtering for quality and recency.\nThese can potentially be used to find new peers in the network.\nThe total number of addresses known to the node may be higher.\n\nArguments:\n1. count      (numeric, optional, default=1) The maximum number of addresses to return. Specify 0 to return all known addresses.\n2. network    (string, optional, default=all networks) Return only addresses of the specified network. Can be one of: ipv4, ipv6, onion, i2p, cjdns.\n\nResult:\n[                         (json array)\n  {                       (json object)\n    \"time\" : xxx,         (numeric) The UNIX epoch time when the node was last seen\n    \"services\" : n,       (numeric) The services offered by the node\n    \"address\" : \"str\",    (string) The address of the node\n    \"port\" : n,           (numeric) The port number of the node\n    \"network\" : \"str\"     (string) The network (ipv4, ipv6, onion, i2p, cjdns) the node connected through\n  },\n  ...\n]\n\nExamples:\n> bitcoin-cli getnodeaddresses 8\n> bitcoin-cli getnodeaddresses 4 \"i2p\"\n> bitcoin-cli -named getnodeaddresses network=onion count=12\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getnodeaddresses\", \"params\": [8]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getnodeaddresses\", \"params\": [4, \"i2p\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help addpeeraddress` text (Bitcoin Core 29).
const ADDPEERADDRESS_HELP: &str = "addpeeraddress \"address\" port ( tried )\n\nAdd the address of a potential peer to an address manager table. This RPC is for testing only.\n\nArguments:\n1. address    (string, required) The IP address of the peer\n2. port       (numeric, required) The port of the peer\n3. tried      (boolean, optional, default=false) If true, attempt to add the peer to the tried addresses table\n\nResult:\n{                            (json object)\n  \"success\" : true|false,    (boolean) whether the peer address was successfully added to the address manager table\n  \"error\" : \"str\"            (string, optional) error description, if the address could not be added\n}\n\nExamples:\n> bitcoin-cli addpeeraddress \"1.2.3.4\" 8333 true\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"addpeeraddress\", \"params\": [\"1.2.3.4\", 8333, true]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getdeploymentinfo` text (Knots 29.3).
const GETDEPLOYMENTINFO_HELP: &str = "getdeploymentinfo ( \"blockhash\" )\n\nReturns an object containing various state info regarding deployments of consensus changes.\n\nArguments:\n1. blockhash    (string, optional, default=\"hash of current chain tip\") The block hash at which to query deployment state\n\nResult:\n{                                       (json object)\n  \"hash\" : \"str\",                       (string) requested block hash (or tip)\n  \"height\" : n,                         (numeric) requested block height (or tip)\n  \"deployments\" : {                     (json object)\n    \"xxxx\" : {                          (json object) name of the deployment\n      \"type\" : \"str\",                   (string) one of \"buried\", \"bip9\"\n      \"height\" : n,                     (numeric, optional) height of the first block which enforces the rules (only for \"buried\" type, or \"bip9\" type with \"active\" status)\n      \"height_end\" : n,                 (numeric, optional) height of the last block which enforces the rules (only for \"bip9\" type with \"active\" status and temporary deployments)\n      \"active\" : true|false,            (boolean) true if the rules are enforced for the mempool and the next block\n      \"bip9\" : {                        (json object, optional) status of bip9 softforks (only for \"bip9\" type)\n        \"bit\" : n,                      (numeric, optional) the bit (0-28) in the block version field used to signal this softfork (only for \"started\" and \"locked_in\" status)\n        \"start_time\" : xxx,             (numeric) the minimum median time past of a block at which the bit gains its meaning\n        \"timeout\" : xxx,                (numeric) the median time past of a block at which the deployment is considered failed if not yet locked in\n        \"min_activation_height\" : n,    (numeric) minimum height of blocks for which the rules may be enforced\n        \"max_activation_height\" : n,    (numeric, optional) height at which the deployment will unconditionally activate (absent for miner-vetoable deployments)\n        \"status\" : \"str\",               (string) status of deployment at specified block (one of \"defined\", \"started\", \"locked_in\", \"active\", \"failed\", \"expired\")\n        \"since\" : n,                    (numeric) height of the first block to which the status applies\n        \"status_next\" : \"str\",          (string) status of deployment at the next block\n        \"statistics\" : {                (json object, optional) numeric statistics about signalling for a softfork (only for \"started\" and \"locked_in\" status)\n          \"period\" : n,                 (numeric) the length in blocks of the signalling period\n          \"period_start\" : n,           (numeric) height of the first block of this signalling period\n          \"threshold\" : n,              (numeric, optional) the number of blocks with the version bit set required to activate the feature (only for \"started\" status)\n          \"elapsed\" : n,                (numeric) the number of blocks elapsed since the beginning of the current period\n          \"count\" : n,                  (numeric) the number of blocks with the version bit set in the current period\n          \"possible\" : true|false       (boolean, optional) returns false if there are not enough blocks left in this period to pass activation threshold (only for \"started\" status)\n        },\n        \"signalling\" : \"str\"            (string, optional) indicates blocks that signalled with a # and blocks that did not with a -\n      }\n    },\n    ...\n  }\n}\n\nExamples:\n> bitcoin-cli getdeploymentinfo \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getdeploymentinfo\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help gettxoutproof` text (Knots 29.3 — witness-proof form).
const GETTXOUTPROOF_HELP: &str = "gettxoutproof [\"txid\",...] ( \"blockhash\" {\"prove_witness\":bool,...} )\n\nReturns a hex-encoded proof that \"txid\" was included in a block.\n\nNOTE: By default this function only works sometimes. This is when there is an\nunspent output in the utxo for this transaction. To make it always work,\nyou need to maintain a transaction index, using the -txindex command line option or\nspecify the block in which the transaction is included manually (by blockhash).\n\nArguments:\n1. txids          (json array, required) The txids to filter\n     [\n       \"txid\",    (string) A transaction id\n       ...\n     ]\n2. blockhash      (string, optional) If specified, looks for txid in the block with this hash\n3. options        (json object, optional) Options object that can be used to pass named arguments, listed below.\n\nNamed Arguments:\nprove_witness    (boolean, optional, default=false) If true, proves the associated wtxid/hash of the specified transactions instead of txid\n\nResult (If prove_witness is false or unspecified):\n\"str\"    (string) A string that is a serialized, hex-encoded data for the proof.\n\nResult (If prove_witness is true):\n{                            (json object)\n  \"proof\" : \"str\",           (string) The produced txout proof, hex-encoded.\n  \"proven\" : {               (json object) Information about the proof.\n    \"blockhash\" : \"hex\",     (string) The block hash the proof links to\n    \"blockheight\" : n,       (numeric) The height of the block the proof links to\n    \"tx\" : [                 (json array) Information about transactions\n      {                      (json object) Information about a transaction\n        \"txid\" : \"hex\",      (string) Transaction id this is for (parameter; NOT proven by proof)\n        \"wtxid\" : \"hex\",     (string) Wtxid/hash of a transaction\n        \"blockindex\" : n     (numeric) Index of transaction in block\n      },\n      ...\n    ]\n  }\n}\n";

/// Verbatim `help verifytxoutproof` text (Knots 29.3).
const VERIFYTXOUTPROOF_HELP: &str = "verifytxoutproof \"proof\" ( {\"verify_witness\":bool,...} )\n\nVerifies that a proof points to a transaction in a block, returning the transaction it commits to\nand throwing an RPC error if the block is not in our best chain\n\nArguments:\n1. proof      (string, required) The hex-encoded proof generated by gettxoutproof\n2. options    (json object, optional) Options object that can be used to pass named arguments, listed below.\n\nNamed Arguments:\nverify_witness    (boolean, optional, default=false) If true, also verifies the associated wtxid/hash of the specified transactions (if included in proof)\n\nResult (If verify_witness is false or unspecified):\n[           (json array)\n  \"hex\",    (string) The txid(s) which the proof commits to, or empty array if the proof cannot be validated.\n  ...\n]\n\nResult (If verify_witness is true and the proof valid):\n{                                 (json object)\n  \"blockhash\" : \"hex\",            (string) The block hash this proof links to\n  \"blockheight\" : n,              (numeric) The height of the block this proof links to\n  \"confirmations\" : n,            (numeric, optional) Number of blocks (including the one with the transactions) confirming these transactions\n  \"confirmations_assumed\" : n,    (numeric, optional) The number of unverified blocks confirming these transactions (eg, in an assumed-valid UTXO set)\n  \"tx\" : [                        (json array) Information about transactions\n    {                             (json object) Information about a transaction\n      \"wtxid\" : \"hex\",            (string) Wtxid/hash of a transaction\n      \"blockindex\" : n            (numeric) Index of transaction in block\n    },\n    ...\n  ]\n}\n\nResult (If verify_witness is true and the proof invalid):\n{}    (empty JSON object)\n";

/// Verbatim `help getindexinfo` text (Bitcoin Core 29).
const GETINDEXINFO_HELP: &str = "getindexinfo ( \"index_name\" )\n\nReturns the status of one or all available indices currently running in the node.\n\nArguments:\n1. index_name    (string, optional) Filter results for an index with a specific name.\n\nResult:\n{                               (json object)\n  \"name\" : {                    (json object) The name of the index\n    \"synced\" : true|false,      (boolean) Whether the index is synced or not\n    \"best_block_height\" : n     (numeric) The block height to which the index is synced\n  },\n  ...\n}\n\nExamples:\n> bitcoin-cli getindexinfo \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getindexinfo\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n> bitcoin-cli getindexinfo txindex\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getindexinfo\", \"params\": [txindex]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help preciousblock` text (Bitcoin Core 29.4).
const PRECIOUSBLOCK_HELP: &str = "preciousblock \"blockhash\"\n\nTreats a block as if it were received before others with the same work.\n\nA later preciousblock call can override the effect of an earlier one.\n\nThe effects of preciousblock are not retained across restarts.\n\nArguments:\n1. blockhash    (string, required) the hash of the block to mark as precious\n\nResult:\nnull    (json null)\n\nExamples:\n> bitcoin-cli preciousblock \"blockhash\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"preciousblock\", \"params\": [\"blockhash\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

const GETCHAINTXSTATS_HELP: &str = "getchaintxstats ( nblocks \"blockhash\" )\n\nCompute statistics about the total number and rate of transactions in the chain.\n\nArguments:\n1. nblocks      (numeric, optional, default=one month) Size of the window in number of blocks\n2. blockhash    (string, optional, default=chain tip) The hash of the block that ends the window.\n\nResult:\n{                                       (json object)\n  \"time\" : xxx,                         (numeric) The timestamp for the final block in the window, expressed in UNIX epoch time\n  \"txcount\" : n,                        (numeric, optional) The total number of transactions in the chain up to that point, if known. It may be unknown when using assumeutxo.\n  \"window_final_block_hash\" : \"hex\",    (string) The hash of the final block in the window\n  \"window_final_block_height\" : n,      (numeric) The height of the final block in the window.\n  \"window_block_count\" : n,             (numeric) Size of the window in number of blocks\n  \"window_interval\" : n,                (numeric, optional) The elapsed time in the window in seconds. Only returned if \"window_block_count\" is > 0\n  \"window_tx_count\" : n,                (numeric, optional) The number of transactions in the window. Only returned if \"window_block_count\" is > 0 and if txcount exists for the start and end of the window.\n  \"txrate\" : n                          (numeric, optional) The average rate of transactions per second in the window. Only returned if \"window_interval\" is > 0 and if window_tx_count exists.\n}\n\nExamples:\n> bitcoin-cli getchaintxstats \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getchaintxstats\", \"params\": [2016]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help gettxoutsetinfo` text (Bitcoin Core 29.4).
const GETTXOUTSETINFO_HELP: &str = "gettxoutsetinfo ( \"hash_type\" hash_or_height use_index )\n\nReturns statistics about the unspent transaction output set.\nNote this call may take some time if you are not using coinstatsindex.\n\nArguments:\n1. hash_type         (string, optional, default=\"hash_serialized_3\") Which UTXO set hash should be calculated. Options: 'hash_serialized_3' (the legacy algorithm), 'muhash', 'none'.\n2. hash_or_height    (string or numeric, optional, default=the current best block) The block hash or height of the target height (only available with coinstatsindex).\n3. use_index         (boolean, optional, default=true) Use coinstatsindex, if available.\n\nResult:\n{                                     (json object)\n  \"height\" : n,                       (numeric) The block height (index) of the returned statistics\n  \"bestblock\" : \"hex\",                (string) The hash of the block at which these statistics are calculated\n  \"txouts\" : n,                       (numeric) The number of unspent transaction outputs\n  \"bogosize\" : n,                     (numeric) Database-independent, meaningless metric indicating the UTXO set size\n  \"hash_serialized_3\" : \"hex\",        (string, optional) The serialized hash (only present if 'hash_serialized_3' hash_type is chosen)\n  \"muhash\" : \"hex\",                   (string, optional) The serialized hash (only present if 'muhash' hash_type is chosen)\n  \"transactions\" : n,                 (numeric, optional) The number of transactions with unspent outputs (not available when coinstatsindex is used)\n  \"disk_size\" : n,                    (numeric, optional) The estimated size of the chainstate on disk (not available when coinstatsindex is used)\n  \"total_amount\" : n,                 (numeric) The total amount of coins in the UTXO set\n  \"total_unspendable_amount\" : n,     (numeric, optional) The total amount of coins permanently excluded from the UTXO set (only available if coinstatsindex is used)\n  \"block_info\" : {                    (json object, optional) Info on amounts in the block at this block height (only available if coinstatsindex is used)\n    \"prevout_spent\" : n,              (numeric) Total amount of all prevouts spent in this block\n    \"coinbase\" : n,                   (numeric) Coinbase subsidy amount of this block\n    \"new_outputs_ex_coinbase\" : n,    (numeric) Total amount of new outputs created by this block\n    \"unspendable\" : n,                (numeric) Total amount of unspendable outputs created in this block\n    \"unspendables\" : {                (json object) Detailed view of the unspendable categories\n      \"genesis_block\" : n,            (numeric) The unspendable amount of the Genesis block subsidy\n      \"bip30\" : n,                    (numeric) Transactions overridden by duplicates (no longer possible with BIP30)\n      \"scripts\" : n,                  (numeric) Amounts sent to scripts that are unspendable (for example OP_RETURN outputs)\n      \"unclaimed_rewards\" : n         (numeric) Fee rewards that miners did not claim in their coinbase transaction\n    }\n  }\n}\n\nExamples:\n> bitcoin-cli gettxoutsetinfo \n> bitcoin-cli gettxoutsetinfo \"none\"\n> bitcoin-cli gettxoutsetinfo \"none\" 1000\n> bitcoin-cli gettxoutsetinfo \"none\" '\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"'\n> bitcoin-cli -named gettxoutsetinfo hash_type='muhash' use_index='false'\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"gettxoutsetinfo\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"gettxoutsetinfo\", \"params\": [\"none\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"gettxoutsetinfo\", \"params\": [\"none\", 1000]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"gettxoutsetinfo\", \"params\": [\"none\", \"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getblockfrompeer` text (Bitcoin Core 29.4).
const GETBLOCKFROMPEER_HELP: &str = "getblockfrompeer \"blockhash\" peer_id\n\nAttempt to fetch block from a given peer.\n\nWe must have the header for this block, e.g. using submitheader.\nThe block will not have any undo data which can limit the usage of the block data in a context where the undo data is needed.\nSubsequent calls for the same block may cause the response from the previous peer to be ignored.\nPeers generally ignore requests for a stale block that they never fully verified, or one that is more than a month old.\nWhen a peer does not respond with a block, we will disconnect.\nNote: The block could be re-pruned as soon as it is received.\n\nReturns an empty JSON object if the request was successfully scheduled.\n\nArguments:\n1. blockhash    (string, required) The block hash to try to fetch\n2. peer_id      (numeric, required) The peer to fetch it from (see getpeerinfo for peer IDs)\n\nResult:\n{}    (empty JSON object)\n\nExamples:\n> bitcoin-cli getblockfrompeer \"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getblockfrompeer\", \"params\": [\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\" 0]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help prioritisetransaction` text (Bitcoin Core 29.4).
const PRIORITISETRANSACTION_HELP: &str = "prioritisetransaction \"txid\" ( dummy ) fee_delta\n\nAccepts the transaction into mined blocks at a higher (or lower) priority\n\nArguments:\n1. txid         (string, required) The transaction id.\n2. dummy        (numeric, optional) API-Compatibility for previous API. Must be zero or null.\n                DEPRECATED. For forward compatibility use named arguments and omit this parameter.\n3. fee_delta    (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n                Note, that this value is not a fee rate. It is a value to modify absolute fee of the TX.\n                The fee is not actually paid, only the algorithm for selecting transactions into a block\n                considers the transaction as it would have paid a higher (or lower) fee.\n\nResult:\ntrue|false    (boolean) Returns true\n\nExamples:\n> bitcoin-cli prioritisetransaction \"txid\" 0.0 10000\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"prioritisetransaction\", \"params\": [\"txid\", 0.0, 10000]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getprioritisedtransactions` text (Bitcoin Core 29).
const CREATEMULTISIG_HELP: &str = "createmultisig nrequired [\"key\",...] ( \"address_type\" )\n\nCreates a multi-signature address with n signature of m keys required.\nIt returns a json object with the address and redeemScript.\n\nArguments:\n1. nrequired       (numeric, required) The number of required signatures out of the n keys.\n2. keys            (json array, required) The hex-encoded public keys.\n     [\n       \"key\",      (string) The hex-encoded public key\n       ...\n     ]\n3. address_type    (string, optional, default=\"legacy\") The address type to use. Options are \"legacy\", \"p2sh-segwit\", and \"bech32\".\n\nResult:\n{                            (json object)\n  \"address\" : \"str\",         (string) The value of the new multisig address.\n  \"redeemScript\" : \"hex\",    (string) The string value of the hex-encoded redemption script.\n  \"descriptor\" : \"str\",      (string) The descriptor for this multisig\n  \"warnings\" : [             (json array, optional) Any warnings resulting from the creation of this multisig\n    \"str\",                   (string)\n    ...\n  ]\n}\n\nExamples:\n\nCreate a multisig address from 2 public keys\n> bitcoin-cli createmultisig 2 \"[\\\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\\\",\\\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\\\"]\"\n\nAs a JSON-RPC call\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"createmultisig\", \"params\": [2, [\"03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd\",\"03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626\"]]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

const VERIFYMESSAGE_HELP: &str = "verifymessage \"address\" \"signature\" \"message\"\n\nVerify a signed message.\n\nArguments:\n1. address      (string, required) The bitcoin address to use for the signature.\n2. signature    (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n3. message      (string, required) The message that was signed.\n\nResult:\ntrue|false    (boolean) If the signature is verified or not.\n\nExamples:\n\nUnlock the wallet for 30 seconds\n> bitcoin-cli walletpassphrase \"mypassphrase\" 30\n\nCreate the signature\n> bitcoin-cli signmessage \"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"my message\"\n\nVerify the signature\n> bitcoin-cli verifymessage \"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"\n\nAs a JSON-RPC call\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"verifymessage\", \"params\": [\"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\", \"signature\", \"my message\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

const SIGNMESSAGEWITHPRIVKEY_HELP: &str = "signmessagewithprivkey \"privkey\" \"message\"\n\nSign a message with the private key of an address\n\nArguments:\n1. privkey    (string, required) The private key to sign the message with.\n2. message    (string, required) The message to create a signature of.\n\nResult:\n\"str\"    (string) The signature of the message encoded in base 64\n\nExamples:\n\nCreate the signature\n> bitcoin-cli signmessagewithprivkey \"privkey\" \"my message\"\n\nVerify the signature\n> bitcoin-cli verifymessage \"1D1ZrZNe3JUo7ZycKEYQQiQAWd9y54F4XX\" \"signature\" \"my message\"\n\nAs a JSON-RPC call\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"signmessagewithprivkey\", \"params\": [\"privkey\", \"my message\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

const GETPRIORITISEDTRANSACTIONS_HELP: &str = "getprioritisedtransactions\n\nReturns a map of all user-created (see prioritisetransaction) fee deltas by txid, and whether the tx is present in mempool.\n\nResult:\n{                                 (json object) prioritisation keyed by txid\n  \"<transactionid>\" : {           (json object)\n    \"fee_delta\" : n,              (numeric) transaction fee delta in satoshis\n    \"in_mempool\" : true|false,    (boolean) whether this transaction is currently in mempool\n    \"modified_fee\" : n            (numeric, optional) modified fee in satoshis. Only returned if in_mempool=true\n  },\n  ...\n}\n\nExamples:\n> bitcoin-cli getprioritisedtransactions \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getprioritisedtransactions\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help waitforblock` text (Bitcoin Core 29.4).
const WAITFORBLOCK_HELP: &str = "waitforblock \"blockhash\" ( timeout )\n\nWaits for a specific new block and returns useful info about it.\n\nReturns the current block on timeout or exit.\n\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)\n\nArguments:\n1. blockhash    (string, required) Block hash to wait for.\n2. timeout      (numeric, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n\nResult:\n{                    (json object)\n  \"hash\" : \"hex\",    (string) The blockhash\n  \"height\" : n       (numeric) Block height\n}\n\nExamples:\n> bitcoin-cli waitforblock \"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\" 1000\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"waitforblock\", \"params\": [\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help waitforblockheight` text (Bitcoin Core 29.4).
const WAITFORBLOCKHEIGHT_HELP: &str = "waitforblockheight height ( timeout )\n\nWaits for (at least) block height and returns the height and hash\nof the current tip.\n\nReturns the current block on timeout or exit.\n\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)\n\nArguments:\n1. height     (numeric, required) Block height to wait for.\n2. timeout    (numeric, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n\nResult:\n{                    (json object)\n  \"hash\" : \"hex\",    (string) The blockhash\n  \"height\" : n       (numeric) Block height\n}\n\nExamples:\n> bitcoin-cli waitforblockheight 100 1000\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"waitforblockheight\", \"params\": [100, 1000]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help waitfornewblock` text (Bitcoin Core 29.4).
const WAITFORNEWBLOCK_HELP: &str = "waitfornewblock ( timeout )\n\nWaits for any new block and returns useful info about it.\n\nReturns the current block on timeout or exit.\n\nMake sure to use no RPC timeout (bitcoin-cli -rpcclienttimeout=0)\n\nArguments:\n1. timeout    (numeric, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n\nResult:\n{                    (json object)\n  \"hash\" : \"hex\",    (string) The blockhash\n  \"height\" : n       (numeric) Block height\n}\n\nExamples:\n> bitcoin-cli waitfornewblock 1000\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"waitfornewblock\", \"params\": [1000]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help verifychain` text (Bitcoin Core 29.4).
const VERIFYCHAIN_HELP: &str = "verifychain ( checklevel nblocks )\n\nVerifies blockchain database.\n\nArguments:\n1. checklevel    (numeric, optional, default=3, range=0-4) How thorough the block verification is:\n                 - level 0 reads the blocks from disk\n                 - level 1 verifies block validity\n                 - level 2 verifies undo data\n                 - level 3 checks disconnection of tip blocks\n                 - level 4 tries to reconnect the blocks\n                 - each level includes the checks of the previous levels\n2. nblocks       (numeric, optional, default=6, 0=all) The number of blocks to check.\n\nResult:\ntrue|false    (boolean) Verification finished successfully. If false, check debug.log for reason.\n\nExamples:\n> bitcoin-cli verifychain \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"verifychain\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help setban` text (Bitcoin Core 29.4).
const SETBAN_HELP: &str = "setban \"subnet\" \"command\" ( bantime absolute )\n\nAttempts to add or remove an IP/Subnet from the banned list.\n\nArguments:\n1. subnet      (string, required) The IP/Subnet (see getpeerinfo for nodes IP) with an optional netmask (default is /32 = single IP)\n2. command     (string, required) 'add' to add an IP/Subnet to the list, 'remove' to remove an IP/Subnet from the list\n3. bantime     (numeric, optional, default=0) time in seconds how long (or until when if [absolute] is set) the IP is banned (0 or empty means using the default time of 24h which can also be overwritten by the -bantime startup argument)\n4. absolute    (boolean, optional, default=false) If set, the bantime must be an absolute timestamp expressed in UNIX epoch time\n\nResult:\nnull    (json null)\n\nExamples:\n> bitcoin-cli setban \"192.168.0.6\" \"add\" 86400\n> bitcoin-cli setban \"192.168.0.0/24\" \"add\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"setban\", \"params\": [\"192.168.0.6\", \"add\", 86400]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help listbanned` text (Bitcoin Core 29.4).
const LISTBANNED_HELP: &str = "listbanned\n\nList all manually banned IPs/Subnets.\n\nResult:\n[                              (json array)\n  {                            (json object)\n    \"address\" : \"str\",         (string) The IP/Subnet of the banned node\n    \"ban_created\" : xxx,       (numeric) The UNIX epoch time the ban was created\n    \"banned_until\" : xxx,      (numeric) The UNIX epoch time the ban expires\n    \"ban_duration\" : xxx,      (numeric) The ban duration, in seconds\n    \"time_remaining\" : xxx     (numeric) The time remaining until the ban expires, in seconds\n  },\n  ...\n]\n\nExamples:\n> bitcoin-cli listbanned \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"listbanned\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help clearbanned` text (Bitcoin Core 29.4).
const CLEARBANNED_HELP: &str = "clearbanned\n\nClear all banned IPs.\n\nResult:\nnull    (json null)\n\nExamples:\n> bitcoin-cli clearbanned \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"clearbanned\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

const GETRPCINFO_HELP: &str = "getrpcinfo\n\nReturns details of the RPC server.\n\nResult:\n{                          (json object)\n  \"active_commands\" : [    (json array) All active commands\n    {                      (json object) Information about an active command\n      \"method\" : \"str\",    (string) The name of the RPC command\n      \"duration\" : n       (numeric) The running time in microseconds\n    },\n    ...\n  ],\n  \"logpath\" : \"str\"        (string) The complete file path to the debug log\n}\n\nExamples:\n> bitcoin-cli getrpcinfo \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getrpcinfo\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

const GETMEMORYINFO_HELP: &str = "getmemoryinfo ( \"mode\" )\n\nReturns an object containing information about memory usage.\n\nArguments:\n1. mode    (string, optional, default=\"stats\") determines what kind of information is returned.\n           - \"stats\" returns general statistics about memory usage in the daemon.\n           - \"mallocinfo\" returns an XML string describing low-level heap state (only available if compiled with glibc).\n\nResult (mode \"stats\"):\n{                         (json object)\n  \"locked\" : {            (json object) Information about locked memory manager\n    \"used\" : n,           (numeric) Number of bytes used\n    \"free\" : n,           (numeric) Number of bytes available in current arenas\n    \"total\" : n,          (numeric) Total number of bytes managed\n    \"locked\" : n,         (numeric) Amount of bytes that succeeded locking. If this number is smaller than total, locking pages failed at some point and key data could be swapped to disk.\n    \"chunks_used\" : n,    (numeric) Number allocated chunks\n    \"chunks_free\" : n     (numeric) Number unused chunks\n  }\n}\n\nResult (mode \"mallocinfo\"):\n\"str\"    (string) \"<malloc version=\"1\">...\"\n\nExamples:\n> bitcoin-cli getmemoryinfo \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getmemoryinfo\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

const LOGGING_HELP: &str = "logging ( [\"include_category\",...] [\"exclude_category\",...] )\n\nGets and sets the logging configuration.\nWhen called without an argument, returns the list of categories with status that are currently being debug logged or not.\nWhen called with arguments, adds or removes categories from debug logging and return the lists above.\nThe arguments are evaluated in order \"include\", \"exclude\".\nIf an item is both included and excluded, it will thus end up being excluded.\nThe valid logging categories are: addrman, bench, blockstorage, cmpctblock, coindb, estimatefee, http, i2p, ipc, leveldb, libevent, mempool, mempoolrej, net, proxy, prune, qt, rand, reindex, rpc, scan, selectcoins, tor, txpackages, txreconciliation, validation, walletdb, zmq\nIn addition, the following are available as category names with special meanings:\n  - \"all\",  \"1\" : represent all logging categories.\n\nArguments:\n1. include                    (json array, optional) The categories to add to debug logging\n     [\n       \"include_category\",    (string) the valid logging category\n       ...\n     ]\n2. exclude                    (json array, optional) The categories to remove from debug logging\n     [\n       \"exclude_category\",    (string) the valid logging category\n       ...\n     ]\n\nResult:\n{                             (json object) keys are the logging categories, and values indicates its status\n  \"category\" : true|false,    (boolean) if being debug logged or not. false:inactive, true:active\n  ...\n}\n\n";

fn missing_params(what: &str) -> (Value, Option<(i64, String)>) {
    (
        Value::Null,
        Some((RPC_INVALID_PARAMS, format!("missing parameter: {what}"))),
    )
}

/// Core's `GetNetworkHashPS` (rpc/mining.cpp): the chainwork delta
/// over the `lookup`-block window ending at `height` (-1 = tip),
/// divided by the window's min→max timestamp span. `lookup <= 0`
/// means "since the last difficulty change" (`height % interval + 1`);
/// a lookup past the window start clamps to the block's own height.
/// Zero on genesis or a timestamp-degenerate window (min == max).
fn network_hashps(cs: &Chainstate, lookup: i64, height: i64) -> f64 {
    let chain = cs.chain();
    let h = if height < 0 {
        chain.len() as i64 - 1
    } else {
        height
    };
    let Some(node) = chain
        .get(usize::try_from(h).unwrap_or(usize::MAX))
        .and_then(|hash| cs.tree().get(hash))
    else {
        return 0.0;
    };
    if node.height == 0 {
        return 0.0;
    }
    let mut lookup = if lookup <= 0 {
        i64::from(node.height) % cs.tree().params().difficulty_adjustment_interval() as i64 + 1
    } else {
        lookup
    };
    lookup = lookup.min(i64::from(node.height));
    let start_h = node.height - lookup as u32;
    let (mut min_t, mut max_t) = (node.header.time, node.header.time);
    for hh in start_h..node.height {
        if let Some(n) = chain.get(hh as usize).and_then(|hash| cs.tree().get(hash)) {
            min_t = min_t.min(n.header.time);
            max_t = max_t.max(n.header.time);
        }
    }
    if min_t == max_t {
        return 0.0;
    }
    chain
        .get(start_h as usize)
        .and_then(|hash| cs.tree().get(hash))
        .and_then(|base| node.chainwork.0.checked_sub(base.chainwork.0))
        .map(|w| w.to_f64() / f64::from(max_t - min_t))
        .unwrap_or(0.0)
}

/// Core's `GetDifficulty` (pow.cpp), matching bitcoind's printed value.
fn difficulty(bits: u32) -> f64 {
    difficulty_from_compact(avila_consensus::arith::CompactTarget(bits))
}

/// The `Value` Core's UniValue emits for a double: `std::setprecision(16)`
/// on an ostream is C `%.16g` — 16 significant digits, trailing zeros and
/// the decimal point stripped. Two consequences: a 17-digit round-trip
/// value gets emitted as a *different* double (regtest `difficulty`), and
/// an integral value prints as `1`, not `1.0`. Reproduce both: format to
/// 16 sig digits, then emit an i64 when the text is integer-form.
fn core_num(v: f64) -> Value {
    let sci = format!("{v:.15e}");
    let (mant, exp) = sci.split_once('e').unwrap_or((sci.as_str(), "0"));
    let exp: i32 = exp.parse().unwrap_or(0);
    let text = if (-4..16).contains(&exp) {
        // %g fixed notation: shift the decimal point into the mantissa.
        let digits: String = mant.chars().filter(|c| *c != '.').collect();
        let (sign, digits) = digits
            .strip_prefix('-')
            .map_or(("", digits.as_str()), |d| ("-", d));
        let point = (exp + 1).max(0) as usize;
        let mut s = String::from(sign);
        if point >= digits.len() {
            s.push_str(digits);
            s.push_str(&"0".repeat(point - digits.len()));
        } else if point == 0 {
            s.push_str("0.");
            s.push_str(&"0".repeat((-exp - 1) as usize));
            s.push_str(digits);
        } else {
            s.push_str(&digits[..point]);
            s.push('.');
            s.push_str(&digits[point..]);
        }
        while s.contains('.') && s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
        s
    } else {
        // %g scientific: mantissa without trailing zeros, `e±NN` exponent.
        let mut m = mant.trim_end_matches('0').to_string();
        if m.ends_with('.') {
            m.pop();
        }
        format!("{m}e{exp:+03}")
    };
    if !text.contains(['.', 'e', 'E'])
        && let Ok(i) = text.parse::<i64>()
    {
        return json!(i);
    }
    json!(text.parse::<f64>().unwrap_or(v))
}

/// Decode a service bitfield the way Core's `servicesnames` does —
/// known bits named, unknown bits reported as `UNKNOWN[2^n]`.
fn service_names(services: u64) -> Vec<String> {
    const KNOWN: &[(u64, &str)] = &[
        (1 << 0, "NETWORK"),
        (1 << 1, "GETUTXO"),
        (1 << 2, "BLOOM"),
        (1 << 3, "WITNESS"),
        (1 << 6, "COMPACT_FILTERS"),
        (1 << 10, "NETWORK_LIMITED"),
        (1 << 11, "P2P_V2"),
    ];
    let mut names = Vec::new();
    let mut seen = 0u64;
    for (bit, name) in KNOWN {
        if services & bit != 0 {
            names.push((*name).to_string());
            seen |= bit;
        }
    }
    let mut unknown = services & !seen;
    let mut bit = 0;
    while unknown != 0 {
        if unknown & 1 != 0 {
            names.push(format!("UNKNOWN[2^{bit}]"));
        }
        unknown >>= 1;
        bit += 1;
    }
    names
}

/// Whether `hash` sits on the active (connected, fully validated) chain.
fn on_active_chain(cs: &Chainstate, hash: &BlockHash, height: u32) -> bool {
    cs.chain().get(height as usize) == Some(hash)
}

// Core's getdeploymentinfo — rpc/deploymentinfo.cpp.
fn deploymentinfo_json(cs: &Chainstate, node: &HeaderNode) -> Value {
    use avila_consensus::bip9::{self, Bip9State};
    let params = cs.tree().params();
    let mut deployments = serde_json::Map::new();
    for (name, height) in [
        ("bip34", params.bip34_height),
        ("bip66", params.bip66_height),
        ("bip65", params.bip65_height),
        ("csv", params.csv_height),
        ("segwit", params.segwit_height),
    ] {
        // DeploymentActiveAfter: active for the block following
        // `node`, i.e. node.height + 1 >= deployment height.
        let active = u64::from(node.height) + 1 >= u64::from(height);
        deployments.insert(
            name.to_string(),
            json!({
                "type": "buried",
                "active": active,
                "height": height,
            }),
        );
    }
    for dep in params.bip9_deployments.iter() {
        // Next state = state given `node` as pindexPrev; current state
        // is computed at node's own parent (both are period-aligned).
        // Genesis has no parent: pindexPrev = nullptr → DEFINED.
        let parent = (node.height > 0).then_some(&node.header.prev_block_hash);
        let next = bip9::state(cs.tree(), Some(&node.hash()), dep, params);
        let cur = bip9::state(cs.tree(), parent, dep, params);
        let signalling = matches!(cur, Bip9State::Started | Bip9State::LockedIn);
        let mut bip = serde_json::Map::new();
        if signalling {
            bip.insert("bit".into(), json!(dep.bit));
        }
        bip.insert("start_time".into(), json!(dep.start_time));
        bip.insert("timeout".into(), json!(dep.timeout));
        bip.insert(
            "min_activation_height".into(),
            json!(dep.min_activation_height),
        );
        bip.insert("status".into(), json!(cur.name()));
        bip.insert(
            "since".into(),
            json!(bip9::state_since(cs.tree(), parent, dep, params)),
        );
        bip.insert("status_next".into(), json!(next.name()));
        if signalling {
            // GetStateStatisticsFor evaluates the window containing the
            // *current* block — Core passes the blockindex itself.
            let stats = bip9::stats(cs.tree(), &node.hash(), dep, params);
            bip.insert(
                "statistics".into(),
                json!({
                    "period": stats.period,
                    "elapsed": stats.elapsed,
                    "count": stats.count,
                    "threshold": stats.threshold,
                    "possible": stats.possible,
                }),
            );
            let s: String = stats
                .signalling
                .iter()
                .map(|&b| if b { '#' } else { '-' })
                .collect();
            bip.insert("signalling".into(), json!(s));
        }
        let mut d = serde_json::Map::new();
        d.insert("type".into(), json!("bip9"));
        if next == Bip9State::Active {
            d.insert(
                "height".into(),
                json!(bip9::state_since(
                    cs.tree(),
                    Some(&node.hash()),
                    dep,
                    params
                )),
            );
        }
        d.insert("active".into(), json!(next == Bip9State::Active));
        d.insert("bip9".into(), Value::Object(bip));
        deployments.insert(dep.name.to_string(), Value::Object(d));
    }
    json!({
        "hash": node.hash().to_string(),
        "height": node.height,
        "deployments": deployments,
    })
}

/// The Core-shaped header object shared by `getblockheader`/`getblock`.
fn header_json(cs: &Chainstate, node: &HeaderNode) -> Value {
    let hash = node.hash();
    let tip_height = cs.tree().tip().height;
    let active = on_active_chain(cs, &hash, node.height);
    let mut out = json!({
        "hash": hash.to_string(),
        // Core: -1 for blocks not on the active chain.
        "confirmations": if active {
            i64::from(tip_height - node.height) + 1
        } else {
            -1
        },
        "height": node.height,
        "version": node.header.version,
        "versionHex": format!("{:08x}", node.header.version as u32),
        "merkleroot": node.header.merkle_root.to_string(),
        "time": node.header.time,
        "mediantime": cs
            .tree()
            .median_time_past(&hash)
            .unwrap_or(node.header.time),
        "nonce": node.header.nonce,
        "bits": format!("{:08x}", node.header.bits.0),
        "target": node.header.bits.expand().value.to_hex(),
        "difficulty": core_num(difficulty(node.header.bits.0)),
        "chainwork": node.chainwork.0.to_hex(),
    });
    if !node.header.prev_block_hash.is_zero() {
        out["previousblockhash"] = json!(node.header.prev_block_hash.to_string());
    }
    // `nextblockhash` exists only for non-tip blocks on the active chain.
    if active
        && node.height < tip_height
        && let Some(next) = cs.chain().get(node.height as usize + 1)
    {
        out["nextblockhash"] = json!(next.to_string());
    }
    out
}

/// Core's `PER_UTXO_OVERHEAD` — `sizeof(COutPoint) + sizeof(uint32_t)
/// `+ sizeof(bool)` = 36 + 4 + 1 = 41 bytes of UTXO-set overhead
/// attributed to every coin created or destroyed.
const PER_UTXO_OVERHEAD: i64 = 41;

/// The serialized size of a [`TxOut`]: `value || compactsize(script
/// len) || script` — Core's `GetSerializeSize(CTxOut)`.
fn txout_ser_size(out: &avila_consensus::transaction::TxOut) -> i64 {
    (8 + avila_consensus::encode::compact_size_len(out.script_pubkey.as_bytes().len() as u64)
        + out.script_pubkey.as_bytes().len()) as i64
}

/// Core's `CalculateTruncatedMedian`: sort, middle element, or the
/// mean of the two middles (truncated).
fn truncated_median(scores: &mut [i64]) -> i64 {
    if scores.is_empty() {
        return 0;
    }
    scores.sort_unstable();
    let size = scores.len();
    if size.is_multiple_of(2) {
        (scores[size / 2 - 1] + scores[size / 2]) / 2
    } else {
        scores[size / 2]
    }
}

/// Core's `CalculatePercentilesByWeight`: feerates sorted ascending,
/// each weighted by its tx's weight; the 10/25/50/75/90th percentile
/// *weight unit* reads off the element whose cumulative weight first
/// crosses each threshold.
fn percentiles_by_weight(scores: &mut [(i64, i64)], total_weight: i64) -> [i64; 5] {
    let mut result = [0i64; 5];
    if scores.is_empty() {
        return result;
    }
    scores.sort_unstable();
    let weights = [
        total_weight as f64 / 10.0,
        total_weight as f64 / 4.0,
        total_weight as f64 / 2.0,
        total_weight as f64 * 3.0 / 4.0,
        total_weight as f64 * 9.0 / 10.0,
    ];
    let mut next = 0usize;
    let mut cumulative = 0i64;
    for &(feerate, weight) in scores.iter() {
        cumulative += weight;
        while next < 5 && cumulative as f64 >= weights[next] {
            result[next] = feerate;
            next += 1;
        }
    }
    for r in &mut result[next..] {
        *r = scores.last().map_or(0, |(f, _)| *f);
    }
    result
}

/// `getblockstats` — Core's per-block aggregate computation. `undo`
/// carries the coins each non-coinbase tx spent (active-chain heights
/// only); `wanted` restricts the emitted keys when present.
fn getblockstats_json(
    cs: &Chainstate,
    node: &HeaderNode,
    block: &avila_consensus::block::Block,
    undo: Option<&avila_consensus::connect::BlockUndo>,
    wanted: Option<&std::collections::HashSet<String>>,
) -> Value {
    let height = node.height;
    let mut inputs = 0i64;
    let mut outputs = 0i64;
    let mut utxos = 0i64;
    let mut utxo_size_inc = 0i64;
    let mut utxo_size_inc_actual = 0i64;
    let mut total_out = 0i64;
    let mut totalfee = 0i64;
    let mut total_size = 0i64;
    let mut total_weight = 0i64;
    let mut swtotal_size = 0i64;
    let mut swtotal_weight = 0i64;
    let mut swtxs = 0i64;
    let mut maxfee = 0i64;
    let mut maxfeerate = 0i64;
    let mut minfee = i64::MAX;
    let mut minfeerate = i64::MAX;
    let mut maxtxsize = 0i64;
    let mut mintxsize = i64::MAX;
    let mut fee_array = Vec::new();
    let mut feerate_array = Vec::new();
    let mut txsize_array = Vec::new();

    for (i, tx) in block.transactions.iter().enumerate() {
        outputs += tx.outputs.len() as i64;
        let mut tx_total_out = 0i64;
        for out in &tx.outputs {
            tx_total_out += out.value;
            let out_size = txout_ser_size(out) + PER_UTXO_OVERHEAD;
            utxo_size_inc += out_size;
            // Genesis (and BIP30-repeat coinbases) don't touch the UTXO
            // count; unspendable outputs never enter the set.
            if height != 0 && !out.script_pubkey.is_unspendable() {
                utxos += 1;
                utxo_size_inc_actual += out_size;
            }
        }
        if tx.is_coinbase() {
            continue;
        }
        inputs += tx.inputs.len() as i64;
        total_out += tx_total_out;

        let tx_size = tx.encode().len() as i64;
        let weight = tx.weight() as i64;
        txsize_array.push(tx_size);
        maxtxsize = maxtxsize.max(tx_size);
        mintxsize = mintxsize.min(tx_size);
        total_size += tx_size;
        total_weight += weight;
        if tx.has_witness() {
            swtxs += 1;
            swtotal_size += tx_size;
            swtotal_weight += weight;
        }

        // Input values come from the undo record: `txs[i]` holds the
        // coins tx `i` spent (`txs[0]` is the coinbase's empty entry).
        let tx_total_in: i64 = undo
            .and_then(|u| u.txs.get(i))
            .map(|u| {
                u.spent
                    .iter()
                    .map(|coin| {
                        let prev_size = txout_ser_size(&coin.out) + PER_UTXO_OVERHEAD;
                        utxo_size_inc -= prev_size;
                        utxo_size_inc_actual -= prev_size;
                        coin.out.value
                    })
                    .sum()
            })
            .unwrap_or(0);
        let txfee = tx_total_in - tx_total_out;
        fee_array.push(txfee);
        maxfee = maxfee.max(txfee);
        minfee = minfee.min(txfee);
        totalfee += txfee;
        let feerate = if weight > 0 { txfee * 4 / weight } else { 0 };
        feerate_array.push((feerate, weight));
        maxfeerate = maxfeerate.max(feerate);
        minfeerate = minfeerate.min(feerate);
    }

    let ntx = block.transactions.len() as i64;
    let percentile_fees = percentiles_by_weight(&mut feerate_array, total_weight);
    let subsidy = avila_consensus::connect::block_subsidy(height, cs.tree().params());
    let median_time = cs
        .tree()
        .median_time_past(&node.hash())
        .unwrap_or(node.header.time);

    // Emit only the keys Core would: everything by default, the
    // requested subset when the stats array was given.
    let want = |key: &str| wanted.is_none_or(|w| w.contains(key));
    let mut out = json!({});
    for (key, value) in [
        (
            "avgfee",
            json!(if ntx > 1 { totalfee / (ntx - 1) } else { 0 }),
        ),
        (
            "avgfeerate",
            json!(if total_weight > 0 {
                totalfee * 4 / total_weight
            } else {
                0
            }),
        ),
        (
            "avgtxsize",
            json!(if ntx > 1 { total_size / (ntx - 1) } else { 0 }),
        ),
        ("blockhash", json!(node.hash().to_string())),
        ("feerate_percentiles", json!(percentile_fees)),
        ("height", json!(height)),
        ("ins", json!(inputs)),
        ("maxfee", json!(maxfee)),
        ("maxfeerate", json!(maxfeerate)),
        ("maxtxsize", json!(maxtxsize)),
        ("medianfee", json!(truncated_median(&mut fee_array))),
        ("mediantime", json!(median_time)),
        ("mediantxsize", json!(truncated_median(&mut txsize_array))),
        ("minfee", json!(if minfee == i64::MAX { 0 } else { minfee })),
        (
            "minfeerate",
            json!(if minfeerate == i64::MAX {
                0
            } else {
                minfeerate
            }),
        ),
        (
            "mintxsize",
            json!(if mintxsize == i64::MAX { 0 } else { mintxsize }),
        ),
        ("outs", json!(outputs)),
        ("subsidy", json!(subsidy)),
        ("swtotal_size", json!(swtotal_size)),
        ("swtotal_weight", json!(swtotal_weight)),
        ("swtxs", json!(swtxs)),
        ("time", json!(node.header.time)),
        ("total_out", json!(total_out)),
        ("total_size", json!(total_size)),
        ("total_weight", json!(total_weight)),
        ("totalfee", json!(totalfee)),
        ("txs", json!(ntx)),
        ("utxo_increase", json!(outputs - inputs)),
        ("utxo_size_inc", json!(utxo_size_inc)),
        ("utxo_increase_actual", json!(utxos - inputs)),
        ("utxo_size_inc_actual", json!(utxo_size_inc_actual)),
    ] {
        if want(key) {
            out[key] = value;
        }
    }
    out
}

/// `scriptPubKey` in Core's `ScriptPubKeyToUniv` shape: asm rendering,
/// type classification, the address where the template carries one,
/// and the `addr(...)`/`raw(...)` descriptor form Core emits for bare
/// scripts (InferDescriptor without key material).
fn script_pubkey_json(
    script: &avila_consensus::transaction::Script,
    params: &avila_consensus::params::Params,
) -> Value {
    let mut out = json!({
        "asm": script.asm(),
        "desc": avila_consensus::descriptor::script_desc(script, params),
        "hex": hex::encode(script.as_bytes()),
        "type": script.classify().name(),
    });
    if let Some(addr) = avila_consensus::address::script_address(script, params) {
        out["address"] = json!(addr);
    }
    out
}

/// `scriptSig` decode — asm + hex only; input scripts never carry an
/// address. Core's `TxToUniv` passes `fAttemptSighashDecode` here, so
/// DER-sig pushes carry their `[HASHTYPE]` suffix.
fn script_json(script: &avila_consensus::transaction::Script) -> Value {
    json!({
        "asm": script.asm_sighash(),
        "hex": hex::encode(script.as_bytes()),
    })
}

/// Core's `decodescript`: the `script_pubkey_json` decode plus the
/// P2SH and segwit wrap addresses for scripts that could occupy those
/// wrappers. The wraps are omitted for unspendable scripts
/// (`OP_RETURN`, oversize), scripts with invalid opcodes, P2SH
/// itself, and — for `segwit` — any script that already is a witness
/// program (v1+ programs suppress `p2sh` as well: there is no
/// deployed P2SH-v1+ wrap form).
fn decodescript_json(
    script: &avila_consensus::transaction::Script,
    params: &avila_consensus::params::Params,
) -> Value {
    use avila_consensus::script::ScriptType;

    let mut out = script_pubkey_json(script, params);
    // Core's decodescript drops the top-level hex echo (the input is
    // already the hex); the wrapped segwit form keeps its own hex.
    if let Some(obj) = out.as_object_mut() {
        obj.remove("hex");
    }
    if !script.has_valid_ops() || script.is_unspendable() {
        return out;
    }
    let class = script.classify();
    let p2sh_of = |s: &avila_consensus::transaction::Script| {
        avila_consensus::address::base58check(
            params.base58_script_prefix,
            &avila_consensus::hash::hash160(s.as_bytes()),
        )
    };
    let is_p2sh = matches!(class, ScriptType::ScriptHash(_));
    let witness_version = match &class {
        ScriptType::Witness { version, .. } => Some(*version),
        _ => None,
    };
    if !is_p2sh && witness_version.is_none_or(|v| v == 0) {
        out["p2sh"] = json!(p2sh_of(script));
    }
    if !is_p2sh && witness_version.is_none() {
        // The segwit wrap: P2PKH reuses its key hash, bare pubkey
        // hashes to one, and everything else becomes a v0 scripthash
        // of the script itself.
        let subscript = match &class {
            ScriptType::PubKeyHash(hash) => {
                let mut b = vec![0x00, 0x14];
                b.extend_from_slice(hash);
                Script::new(b)
            }
            ScriptType::PubKey(key) => {
                let mut b = vec![0x00, 0x14];
                b.extend_from_slice(&avila_consensus::hash::hash160(key));
                Script::new(b)
            }
            _ => {
                let mut b = vec![0x00, 0x20];
                b.extend_from_slice(&avila_consensus::hash::sha256(script.as_bytes()));
                Script::new(b)
            }
        };
        let mut segwit = script_pubkey_json(&subscript, params);
        // A wrapped multisig keeps its inferred inner descriptor —
        // wsh(multi(...)) — while hash-only wraps degrade to addr().
        if let ScriptType::Multisig { required, keys } = &class {
            let hexes = keys
                .iter()
                .map(|k| hex::encode(k))
                .collect::<Vec<_>>()
                .join(",");
            let body = format!("wsh(multi({required},{hexes}))");
            segwit["desc"] = json!(format!(
                "{body}#{}",
                avila_consensus::descriptor::descriptor_checksum(&body)
            ));
        }
        segwit["p2sh-segwit"] = json!(p2sh_of(&subscript));
        out["segwit"] = segwit;
    }
    out
}

/// A decoded transaction in Core's `getrawtransaction`/`getblock`
/// verbosity-2 shape (`vout` spends omitted).
fn tx_json(tx: &Transaction, params: &avila_consensus::params::Params, include_hex: bool) -> Value {
    let weight = tx.weight();
    let mut out = json!({
        "txid": tx.txid().to_string(),
        "hash": tx.wtxid().to_string(),
        "version": tx.version,
        "size": tx.size_with_witness(),
        "vsize": weight.div_ceil(4),
        "weight": weight,
        "locktime": tx.lock_time,
        "vin": tx.inputs.iter().map(|input| {
            let mut vin = if input.previous_output.is_null() {
                json!({"coinbase": hex::encode(input.script_sig.as_bytes())})
            } else {
                json!({
                    "txid": input.previous_output.txid.to_string(),
                    "vout": input.previous_output.vout,
                    "scriptSig": script_json(&input.script_sig),
                })
            };
            // `txinwitness` precedes `sequence` and applies to
            // coinbase inputs too (witness coinbases carry the
            // 32-byte reserved value).
            if !input.witness.is_empty() {
                vin["txinwitness"] = json!(
                    input
                        .witness
                        .items()
                        .iter()
                        .map(|i| hex::encode(i))
                        .collect::<Vec<_>>()
                );
            }
            vin["sequence"] = json!(input.sequence);
            vin
        }).collect::<Vec<_>>(),
        "vout": tx.outputs.iter().enumerate().map(|(n, out)| {
            json!({
                "value": out.value as f64 / 100_000_000.0,
                "n": n,
                "scriptPubKey": script_pubkey_json(&out.script_pubkey, params),
            })
        }).collect::<Vec<_>>(),
    });
    if include_hex {
        out["hex"] = json!(hex::encode(&tx.encode()));
    }
    out
}

/// A pooled entry in Core's `getmempoolentry` shape — the admission
/// facts plus computed ancestor/descendant package totals.
fn entry_json(
    pool: &avila_mempool::Mempool,
    txid: &Txid,
    entry: &avila_mempool::MempoolEntry,
) -> Value {
    let ancestors = pool.ancestor_txids(&entry.tx);
    let descendants = pool.descendant_txids(txid);
    // Core's entryToJSON: the ancestor/descendant fee totals (and the
    // `ancestor`/`descendant` keys inside `fees`) sum *modified* fees —
    // base plus prioritisetransaction deltas.
    let stat = |set: &std::collections::HashSet<Txid>| -> (usize, usize, i64) {
        let mut size = 0usize;
        let mut fees = 0i64;
        for id in set {
            if let Some(e) = pool.entry(id) {
                size += e.vsize;
                fees += e.modified_fee();
            }
        }
        (set.len(), size, fees)
    };
    let (_acount, asize, afees) = stat(&ancestors);
    let (_dcount, dsize, dfees) = stat(&descendants);
    let modified = entry.modified_fee();
    // `depends`: direct parents present in the pool (Core dedups via a
    // set; we sort for deterministic output). `spentby`: direct
    // children — txids spending any of this tx's outputs.
    let mut depends: Vec<String> = entry
        .tx
        .inputs
        .iter()
        .filter_map(|i| {
            pool.entry(&i.previous_output.txid)
                .map(|_| i.previous_output.txid.to_string())
        })
        .collect();
    depends.sort_unstable();
    depends.dedup();
    let mut spentby: Vec<String> = (0..entry.tx.outputs.len())
        .filter_map(|vout| {
            pool.spent_by(&avila_consensus::transaction::OutPoint {
                txid: *txid,
                vout: vout as u32,
            })
            .map(|s| s.txid().to_string())
        })
        .collect();
    spentby.sort_unstable();
    json!({
        "vsize": entry.vsize,
        "weight": entry.tx.weight(),
        "time": entry.time,
        "height": entry.first_seen_height,
        "wtxid": entry.tx.wtxid().to_string(),
        "fees": {
            "base": entry.fee as f64 / 100_000_000.0,
            "modified": modified as f64 / 100_000_000.0,
            "ancestor": (afees + modified) as f64 / 100_000_000.0,
            "descendant": (dfees + modified) as f64 / 100_000_000.0,
        },
        "ancestorcount": ancestors.len() + 1,
        "ancestorsize": asize + entry.vsize,
        "descendantcount": descendants.len() + 1,
        "descendantsize": dsize + entry.vsize,
        "depends": depends,
        "spentby": spentby,
        "bip125-replaceable": pool.bip125_replaceable(txid),
        "unbroadcast": pool.is_unbroadcast(txid),
    })
}

/// A txid set as a bare array (verbose=false) or Core's verbose map.
fn family_json(
    pool: &avila_mempool::Mempool,
    set: std::collections::HashSet<Txid>,
    verbose: bool,
) -> Value {
    let mut ids: Vec<Txid> = set.into_iter().collect();
    ids.sort_by_key(|a| a.to_string());
    if verbose {
        let map: serde_json::Map<String, Value> = ids
            .iter()
            .filter_map(|txid| {
                pool.entry(txid)
                    .map(|e| (txid.to_string(), entry_json(pool, txid, e)))
            })
            .collect();
        Value::Object(map)
    } else {
        json!(ids.iter().map(|t| t.to_string()).collect::<Vec<_>>())
    }
}

/// Grinds `block`'s nonce until its hash meets `bits` (bounded by
/// `maxtries`, timestamp-bumped on nonce wrap like Core's
/// `GenerateBlock`), then submits it through `accept_block` and, on
/// connect, purges confirmed pool entries and announces the new tip —
/// the shared tail of `generatetoaddress` and `generateblock`.
fn mine_and_connect(
    cs: &mut Chainstate,
    mgr: &mut PeerManager<TcpStream>,
    mut block: avila_consensus::block::Block,
    maxtries: u64,
    now: u32,
) -> Result<String, (i64, String)> {
    let params = *cs.tree().params();
    let mut tries = 0u64;
    while avila_consensus::pow::check_proof_of_work(&block.block_hash(), block.header.bits, &params)
        .is_err()
    {
        tries += 1;
        if tries > maxtries {
            return Err((RPC_MISC_ERROR, "generate: out of tries".to_string()));
        }
        block.header.nonce = block.header.nonce.wrapping_add(1);
        if block.header.nonce == 0 {
            block.header.time += 1;
        }
    }
    match cs.accept_block(&block, now) {
        Ok(avila_consensus::chainstate::Acceptance::Connected { height, .. }) => {
            mgr.mempool().on_block_connected(&block, height);
            mgr.announce_tip(cs);
            Ok(block.block_hash().to_string())
        }
        Ok(avila_consensus::chainstate::Acceptance::AlreadyKnown { .. }) => {
            Err((RPC_VERIFY_ERROR, "duplicate".to_string()))
        }
        Ok(avila_consensus::chainstate::Acceptance::Parked { .. }) => {
            Err((RPC_VERIFY_ERROR, "inconclusive".to_string()))
        }
        Err(rejection) => Err((
            RPC_VERIFY_ERROR,
            format!("Block validation failed: {}", rejection.reason()),
        )),
    }
}

fn dispatch(
    method: &str,
    params: &Value,
    snap: &SyncProgress,
    queries: Option<&QuerySender>,
    waiters: Option<&Arc<BlockWaiters>>,
    stop: Option<&Arc<AtomicBool>>,
) -> (Value, Option<(i64, String)>) {
    // `getrpcinfo` reports the in-flight command's runtime — Core's
    // `g_rpc_interfaces` stamps the start at dispatch.
    let call_start = std::time::Instant::now();
    match method {
        "getblockcount" => (json!(snap.connected_height), None),
        "getbestblockhash" => (
            snap.recent
                .last()
                .map(|(_, h)| json!(h.to_string()))
                .unwrap_or(Value::Null),
            None,
        ),
        "getdifficulty" => chain_query(queries, |cs, _mgr| {
            let tip = cs.tip_hash();
            let node = cs.tree().get(&tip);
            Ok(node
                .map(|n| core_num(difficulty(n.header.bits.0)))
                .unwrap_or(Value::Null))
        }),
        "verifychain" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() > 2 {
                return help_error(VERIFYCHAIN_HELP);
            }
            // RPCHelpMan's type pass: both args numeric; an explicit
            // null is the "use default" marker, not a type error.
            if let Some(v) = arr.first().filter(|v| !(v.is_number() || v.is_null())) {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(1, "checklevel", v, "number"),
                    )),
                );
            }
            if let Some(v) = arr.get(1).filter(|v| !(v.is_number() || v.is_null())) {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(2, "nblocks", v, "number"),
                    )),
                );
            }
            // getInt<int>: non-integral or out-of-range is UniValue's -1.
            let level = match arr.first() {
                None | Some(Value::Null) => 3, // -checklevel default
                Some(v) => match v.as_i64().and_then(|n| i32::try_from(n).ok()) {
                    Some(n) => n,
                    None => {
                        return (
                            Value::Null,
                            Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                        );
                    }
                },
            };
            let depth = match arr.get(1) {
                None | Some(Value::Null) => 6, // -checkdepth default (29.x)
                Some(v) => match v.as_i64() {
                    Some(n) => n,
                    None => {
                        return (
                            Value::Null,
                            Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                        );
                    }
                },
            };
            // Core applies no range gate on either value — VerifyDB
            // clamps depth to the tip and level < 0 checks nothing.
            chain_query(queries, move |cs, _| Ok(json!(cs.verify_tip(level, depth))))
        }
        "getblockchaininfo" => chain_query(queries, |cs, _mgr| {
            let tip = cs.tip_hash();
            let connected = cs.chain().len().saturating_sub(1) as u32;
            let best_header = cs.tree().tip();
            let Some(node) = cs.tree().get(&tip) else {
                return Err((RPC_MISC_ERROR, "tip not indexed".into()));
            };
            // blk*.dat + state files under the store dir — Core sums
            // its blocks/ and chainstate/ trees; our honest floor is
            // the store we own.
            let size_on_disk = cs
                .store()
                .map(|s| {
                    std::fs::read_dir(s.dir())
                        .map(|rd| {
                            rd.filter_map(|e| e.ok())
                                .filter_map(|e| e.metadata().ok())
                                .map(|m| m.len())
                                .sum::<u64>()
                        })
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            Ok(json!({
                "chain": format!("{:?}", cs.tree().params().network).to_lowercase(),
                "blocks": connected,
                "headers": best_header.height,
                "bestblockhash": tip.to_string(),
                "bits": format!("{:08x}", node.header.bits.0),
                "target": node.header.bits.expand().value.to_hex(),
                "difficulty": core_num(difficulty(node.header.bits.0)),
                "time": node.header.time,
                "mediantime": cs
                    .tree()
                    .median_time_past(&tip)
                    .unwrap_or(node.header.time),
                "verificationprogress": core_num(if best_header.height > 0 {
                    connected as f64 / best_header.height as f64
                } else {
                    1.0
                }),
                "initialblockdownload": best_header.height > connected,
                "chainwork": node.chainwork.0.to_hex(),
                "size_on_disk": size_on_disk,
                "pruned": cs.store().and_then(|s| s.pruned_through()).is_some(),
                "warnings": [],
            }))
        }),
        "getdeploymentinfo" => {
            // RPCHelpMan: 0–1 args.
            if params.as_array().is_some_and(|a| a.len() > 1) {
                return help_error(GETDEPLOYMENTINFO_HELP);
            }
            let sel = param(params, 0, "blockhash").cloned();
            chain_query(queries, move |cs, _| {
                let node = match sel {
                    None | Some(Value::Null) => {
                        let tip = cs.tip_hash();
                        cs.tree().get(&tip)
                    }
                    Some(Value::String(s)) => {
                        // ParseHashV wording, as in getblockstats.
                        if s.len() != 64 {
                            return Err((
                                RPC_INVALID_PARAMETER,
                                format!(
                                    "blockhash must be of length 64 (not {}, for '{s}')",
                                    s.len()
                                ),
                            ));
                        }
                        match s.parse::<BlockHash>() {
                            Ok(hash) => Some(cs.tree().get(&hash).ok_or((
                                RPC_INVALID_ADDRESS_OR_KEY,
                                "Block not found".to_string(),
                            ))?),
                            Err(_) => {
                                return Err((
                                    RPC_INVALID_PARAMETER,
                                    format!("blockhash must be hexadecimal string (not '{s}')"),
                                ));
                            }
                        }
                    }
                    Some(v) => {
                        return Err((
                            RPC_TYPE_ERROR,
                            wrong_type_message(1, "blockhash", &v, "string"),
                        ));
                    }
                };
                let Some(node) = node else {
                    return Err((RPC_MISC_ERROR, "tip not indexed".into()));
                };
                Ok(deploymentinfo_json(cs, node))
            })
        }
        // Core's validateaddress — address decode reporting. Without a
        // wallet the wallet-derived fields (ismine, iswatchonly, …)
        // are absent, matching Core run wallet-free.
        "validateaddress" => {
            let Some(addr) = param(params, 0, "address").and_then(Value::as_str) else {
                return missing_params("address");
            };
            let addr = addr.to_owned();
            chain_query(queries, move |cs, _| {
                match validate_address(&addr, cs.tree().params()) {
                    Ok(info) => {
                        // Core re-encodes the destination (canonical
                        // lowercase bech32); fall back to the input.
                        let canonical =
                            script_address(&info.script, cs.tree().params()).unwrap_or(addr);
                        let mut out = json!({
                            "isvalid": true,
                            "address": canonical,
                            "scriptPubKey": hex::encode(info.script.as_bytes()),
                            "iswitness": info.witness.is_some(),
                        });
                        // Core omits isscript on unknown witness
                        // versions (WitnessUnknown has none).
                        if let Some(is_script) = info.is_script {
                            out["isscript"] = json!(is_script);
                        }
                        if let Some((version, program)) = info.witness {
                            out["witness_version"] = json!(version);
                            out["witness_program"] = json!(hex::encode(&program));
                        }
                        Ok(out)
                    }
                    Err((error, locations)) => Ok(json!({
                        "isvalid": false,
                        "error_locations": locations,
                        "error": error,
                    })),
                }
            })
        }
        // Core's verifymessage (rpc/signmessage.cpp) — compact-sig
        // recovery against a P2PKH destination. The check chain:
        // decode → PKHash? → strict base64 → recover+compare, with
        // every signature-level failure collapsing to `false`.
        "verifymessage" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() != 3 {
                return help_error(VERIFYMESSAGE_HELP);
            }
            let names = ["address", "signature", "message"];
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            for (i, name) in names.iter().enumerate() {
                if !arr[i].is_string() {
                    type_errors.push((i + 1, name, &arr[i], "string"));
                }
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            let (addr, sig, msg) = (
                arr[0].as_str().unwrap_or_default().to_owned(),
                arr[1].as_str().unwrap_or_default().to_owned(),
                arr[2].as_str().unwrap_or_default().to_owned(),
            );
            chain_query(queries, move |cs, _| {
                let params = cs.tree().params();
                let Some(script) = avila_consensus::address::address_to_script(&addr, params)
                else {
                    return Err((RPC_INVALID_ADDRESS_OR_KEY, "Invalid address".into()));
                };
                let avila_consensus::script::ScriptType::PubKeyHash(pk_hash) = script.classify()
                else {
                    return Err((RPC_TYPE_ERROR, "Address does not refer to key".into()));
                };
                let Some(sig_bytes) = base64_decode_strict(&sig) else {
                    return Err((RPC_TYPE_ERROR, "Malformed base64 encoding".into()));
                };
                Ok(json!(avila_consensus::message::verify_message(
                    &pk_hash, &sig_bytes, &msg
                )))
            })
        }
        // Core's signmessagewithprivkey — DecodeSecret then the
        // compact-sig MessageSign; the header byte records the WIF's
        // compressed flag so the verifier recovers the right address.
        "signmessagewithprivkey" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() != 2 {
                return help_error(SIGNMESSAGEWITHPRIVKEY_HELP);
            }
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if !arr[0].is_string() {
                type_errors.push((1, "privkey", &arr[0], "string"));
            }
            if !arr[1].is_string() {
                type_errors.push((2, "message", &arr[1], "string"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            let (wif, msg) = (
                arr[0].as_str().unwrap_or_default().to_owned(),
                arr[1].as_str().unwrap_or_default().to_owned(),
            );
            chain_query(queries, move |cs, _| {
                let Some((key, compressed)) = avila_consensus::message::decode_secret(
                    &wif,
                    cs.tree().params().base58_secret_prefix,
                ) else {
                    return Err((RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key".into()));
                };
                let Some(sig) = avila_consensus::message::sign_message(&key, compressed, &msg)
                else {
                    return Err((RPC_INVALID_ADDRESS_OR_KEY, "Sign failed".into()));
                };
                Ok(json!(base64_encode(&sig)))
            })
        }
        "decodescript" => {
            let Some(hexstr) = param(params, 0, "hexstring").and_then(Value::as_str) else {
                return missing_params("hexstring");
            };
            let Ok(bytes) = hex::decode(hexstr) else {
                return (
                    Value::Null,
                    Some((
                        RPC_INVALID_PARAMETER,
                        format!("argument must be hexadecimal string (not '{hexstr}')"),
                    )),
                );
            };
            let script = Script::new(bytes);
            chain_query(queries, move |cs, _| {
                Ok(decodescript_json(&script, cs.tree().params()))
            })
        }
        "decoderawtransaction" => {
            // RPCHelpMan: 1–2 args; anything else is the -1 help throw.
            if params
                .as_array()
                .is_some_and(|a| a.len() > 2 || a.is_empty())
            {
                return help_error(DECODERAWTRANSACTION_HELP);
            }
            let hexstr_val = param(params, 0, "hexstring");
            match hexstr_val {
                None => return help_error(DECODERAWTRANSACTION_HELP),
                Some(v) if !v.is_string() => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(1, "hexstring", v, "string"),
                        )),
                    );
                }
                _ => {}
            }
            let hexstr = hexstr_val.and_then(Value::as_str).unwrap_or_default();
            // Core's `iswitness`: unset tries no-witness then witness,
            // false pins the no-witness parse, true pins witness. A
            // non-bool is Core's -3 type error.
            let iswitness_val = param(params, 1, "iswitness");
            if let Some(v) = iswitness_val
                && !v.is_null()
                && !v.is_boolean()
            {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(2, "iswitness", v, "bool"),
                    )),
                );
            }
            let iswitness = iswitness_val.and_then(Value::as_bool);
            let Ok(bytes) = hex::decode(hexstr) else {
                return (
                    Value::Null,
                    Some((RPC_DESERIALIZATION_ERROR, "TX decode failed".into())),
                );
            };
            let decoded = match iswitness {
                Some(true) => Transaction::decode(&bytes).ok(),
                Some(false) => Transaction::decode_no_witness(&bytes).ok(),
                None => Transaction::decode_no_witness(&bytes)
                    .or_else(|_| Transaction::decode(&bytes))
                    .ok(),
            };
            let Some(tx) = decoded else {
                return (
                    Value::Null,
                    Some((RPC_DESERIALIZATION_ERROR, "TX decode failed".into())),
                );
            };
            chain_query(queries, move |cs, _| {
                Ok(tx_json(&tx, cs.tree().params(), false))
            })
        }
        "getblockhash" => {
            let Some(height) = param(params, 0, "height").and_then(Value::as_u64) else {
                return missing_params("height");
            };
            chain_query(queries, move |cs, _| {
                cs.chain()
                    .get(height as usize)
                    .map(|h| json!(h.to_string()))
                    .ok_or_else(|| (RPC_INVALID_PARAMETER, "Block height out of range".into()))
            })
        }
        "getblockheader" => {
            let Some(hash) = param(params, 0, "blockhash")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<BlockHash>().ok())
            else {
                return missing_params("blockhash");
            };
            let verbose = param(params, 1, "verbose")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            chain_query(queries, move |cs, _| {
                let Some(node) = cs.tree().get(&hash) else {
                    return Err((RPC_INVALID_ADDRESS_OR_KEY, "Block not found".into()));
                };
                if verbose {
                    let mut out = header_json(cs, node);
                    // Core includes nTx only when block data is on disk.
                    if let Some(block) = cs.body(&hash) {
                        out["nTx"] = json!(block.transactions.len());
                    }
                    Ok(out)
                } else {
                    Ok(json!(hex::encode(&node.header.encode())))
                }
            })
        }
        "getblock" => {
            let Some(hash) = param(params, 0, "blockhash")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<BlockHash>().ok())
            else {
                return missing_params("blockhash");
            };
            let verbosity = param(params, 1, "verbosity")
                .and_then(Value::as_u64)
                .unwrap_or(1);
            chain_query(queries, move |cs, _| {
                let Some(node) = cs.tree().get(&hash) else {
                    return Err((RPC_INVALID_ADDRESS_OR_KEY, "Block not found".into()));
                };
                let Some(block) = cs.body(&hash) else {
                    return Err((RPC_MISC_ERROR, "Block not available (pruned data)".into()));
                };
                match verbosity {
                    0 => Ok(json!(hex::encode(&block.encode()))),
                    1 | 2 => {
                        let mut out = header_json(cs, node);
                        out["nTx"] = json!(block.transactions.len());
                        out["size"] = json!(block.size_with_witness());
                        out["strippedsize"] = json!(block.size_without_witness());
                        out["weight"] = json!(block.weight());
                        out["tx"] = if verbosity == 1 {
                            json!(
                                block
                                    .txids()
                                    .iter()
                                    .map(|t| t.to_string())
                                    .collect::<Vec<_>>()
                            )
                        } else {
                            json!(
                                block
                                    .transactions
                                    .iter()
                                    .map(|tx| tx_json(tx, cs.tree().params(), true))
                                    .collect::<Vec<_>>()
                            )
                        };
                        Ok(out)
                    }
                    _ => Err((
                        RPC_INVALID_PARAMS,
                        format!("unsupported verbosity {verbosity} — 0, 1 and 2 are implemented"),
                    )),
                }
            })
        }
        // Core's getblockstats — per-block fee/size/UTXO aggregates.
        // Input values come from the block's undo record (active-chain
        // heights only, like Core's rev*.dat); the optional stats array
        // restricts which keys are emitted.
        "getblockstats" => {
            let Some(selector) = param(params, 0, "hash_or_height") else {
                return missing_params("hash_or_height");
            };
            // The optional stats filter: only these keys are emitted.
            let wanted: Option<std::collections::HashSet<String>> =
                params.get(1).and_then(Value::as_array).map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                });
            let selector = selector.clone();
            chain_query(queries, move |cs, _| {
                // ParseHashOrHeight: a number walks the active chain, a
                // string is a block hash known to the header tree.
                let node = match &selector {
                    Value::Number(n) => {
                        let h = n.as_i64().unwrap_or(i64::MAX);
                        let tip = cs.chain().len() as i64 - 1;
                        if h < 0 {
                            return Err((
                                RPC_INVALID_PARAMETER,
                                format!("Target block height {h} is negative"),
                            ));
                        }
                        if h > tip {
                            return Err((
                                RPC_INVALID_PARAMETER,
                                format!("Target block height {h} after current tip {tip}"),
                            ));
                        }
                        // h ≤ tip, so the active chain has an entry
                        // and the header is necessarily in the tree.
                        let hash = cs.chain()[h as usize];
                        match cs.tree().get(&hash) {
                            Some(n) => n,
                            None => {
                                return Err((
                                    RPC_MISC_ERROR,
                                    "block header missing from tree".to_string(),
                                ));
                            }
                        }
                    }
                    Value::String(s) => {
                        // Core's ParseHashV wording, checked live.
                        if s.len() != 64 {
                            return Err((
                                RPC_INVALID_PARAMETER,
                                format!(
                                    "hash_or_height must be of length 64 (not {}, for '{s}')",
                                    s.len()
                                ),
                            ));
                        }
                        match s.parse::<BlockHash>() {
                            Ok(hash) => cs.tree().get(&hash).ok_or((
                                RPC_INVALID_ADDRESS_OR_KEY,
                                "Block not found".to_string(),
                            ))?,
                            Err(_) => {
                                return Err((
                                    RPC_INVALID_PARAMETER,
                                    format!(
                                        "hash_or_height must be hexadecimal string (not '{s}')"
                                    ),
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err((
                            RPC_INVALID_PARAMS,
                            "missing parameter: hash_or_height".to_string(),
                        ));
                    }
                };
                let height = node.height;
                let hash = node.hash();
                let Some(block) = cs.body(&hash) else {
                    return Err((RPC_MISC_ERROR, "Block not found on disk".into()));
                };
                // Undo exists only for connected active-chain blocks;
                // anything else (genesis is the exception) fails like
                // Core's GetUndoChecked.
                let undo = if height == 0 {
                    None
                } else {
                    match cs.undo(height) {
                        Some(u) if cs.chain().get(height as usize) == Some(&hash) => Some(u),
                        _ => {
                            return Err((RPC_MISC_ERROR, "Can't read undo data from disk".into()));
                        }
                    }
                };
                Ok(getblockstats_json(cs, node, &block, undo, wanted.as_ref()))
            })
        }
        "gettxout" => {
            let Some(txid) = param(params, 0, "txid")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<Txid>().ok())
            else {
                return missing_params("txid");
            };
            let Some(vout) = param(params, 1, "n").and_then(Value::as_u64) else {
                return missing_params("n");
            };
            let include_mempool = param(params, 2, "include_mempool")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            chain_query(queries, move |cs, mgr| {
                let outpoint = OutPoint {
                    txid,
                    vout: vout as u32,
                };
                // With include_mempool (Core's default), an output spent
                // by a pooled transaction reports as spent.
                if include_mempool && mgr.mempool_ref().spent_by(&outpoint).is_some() {
                    return Ok(Value::Null);
                }
                match cs.utxo().get(&outpoint) {
                    None => Ok(Value::Null),
                    Some(coin) => {
                        let tip = cs.chain().len() as u32 - 1;
                        Ok(json!({
                            "bestblock": cs.tip_hash().to_string(),
                            "confirmations": tip - coin.height + 1,
                            "value": coin.out.value as f64 / 100_000_000.0,
                            "scriptPubKey": script_pubkey_json(
                                &coin.out.script_pubkey,
                                cs.tree().params(),
                            ),
                            "coinbase": coin.coinbase,
                        }))
                    }
                }
            })
        }
        "gettxspendingprevout" => {
            // Core's shape: `[{"txid":h,"vout":n},...]` → same list with
            // `spendingtxid` added when the mempool spends the output.
            if params.as_array().is_some_and(|a| a.len() > 1) {
                return help_error(GETTXSPENDINGPREVOUT_HELP);
            }
            let Some(outputs_val) = param(params, 0, "outputs") else {
                return help_error(GETTXSPENDINGPREVOUT_HELP);
            };
            let Some(outputs) = outputs_val.as_array() else {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(1, "outputs", outputs_val, "array"),
                    )),
                );
            };
            if outputs.is_empty() {
                return (
                    Value::Null,
                    Some((
                        RPC_INVALID_PARAMETER,
                        "Invalid parameter, outputs are missing".into(),
                    )),
                );
            }
            let mut outpoints = Vec::with_capacity(outputs.len());
            for item in outputs {
                let Some(obj) = item.as_object() else {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            format!(
                                "JSON value of type {} is not of expected type object",
                                json_type_name(item)
                            ),
                        )),
                    );
                };
                let txid = match obj.get("txid") {
                    Some(v) if !v.is_string() => {
                        return (
                            Value::Null,
                            Some((
                                RPC_TYPE_ERROR,
                                format!(
                                    "JSON value of type {} for field txid is not of \
                                     expected type string",
                                    json_type_name(v)
                                ),
                            )),
                        );
                    }
                    Some(v) => match v.as_str().unwrap_or_default().parse::<Txid>() {
                        Ok(t) => t,
                        Err(_) => {
                            let s = v.as_str().unwrap_or_default();
                            let msg = if s.len() != 64 {
                                format!("txid must be of length 64 (not {}, for '{s}')", s.len())
                            } else {
                                format!("txid must be hexadecimal string (not '{s}')")
                            };
                            return (Value::Null, Some((RPC_INVALID_PARAMETER, msg)));
                        }
                    },
                    None => {
                        return (Value::Null, Some((RPC_TYPE_ERROR, "Missing txid".into())));
                    }
                };
                let vout = match obj.get("vout") {
                    Some(v) if !v.is_number() => {
                        return (
                            Value::Null,
                            Some((
                                RPC_TYPE_ERROR,
                                format!(
                                    "JSON value of type {} for field vout is not of \
                                     expected type number",
                                    json_type_name(v)
                                ),
                            )),
                        );
                    }
                    // Core reads `vout` via `getInt<int>`: non-integer
                    // and out-of-i32-range values are UniValue's
                    // "JSON integer out of range" (-1), then negatives
                    // are the -8 gate.
                    Some(v) => match v.as_i64() {
                        Some(n) if n < 0 => {
                            return (
                                Value::Null,
                                Some((
                                    RPC_INVALID_PARAMETER,
                                    "Invalid parameter, vout cannot be negative".into(),
                                )),
                            );
                        }
                        Some(n) if n > i64::from(i32::MAX) || v.is_f64() => {
                            return (
                                Value::Null,
                                Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                            );
                        }
                        Some(n) => n as u32,
                        None => {
                            return (
                                Value::Null,
                                Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                            );
                        }
                    },
                    None => {
                        return (Value::Null, Some((RPC_TYPE_ERROR, "Missing vout".into())));
                    }
                };
                outpoints.push((OutPoint { txid, vout }, txid.to_string(), u64::from(vout)));
            }
            chain_query(queries, move |cs, mgr| {
                let _ = cs;
                Ok(json!(
                    outpoints
                        .iter()
                        .map(|(op, txid_s, vout)| {
                            let mut entry = json!({"txid": txid_s, "vout": vout});
                            if let Some(tx) = mgr.mempool_ref().spent_by(op) {
                                entry["spendingtxid"] = json!(tx.txid().to_string());
                            }
                            entry
                        })
                        .collect::<Vec<_>>()
                ))
            })
        }
        "gettxoutproof" => {
            // RPCHelpMan: 1–3 args; absent txids → -1 + help.
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.is_empty() || arr.len() > 3 {
                return help_error(GETTXOUTPROOF_HELP);
            }
            let txids_v = match &arr[0] {
                Value::Array(a) => a,
                v => {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(1, "txids", v, "array"))),
                    );
                }
            };
            if txids_v.is_empty() {
                return (
                    Value::Null,
                    Some((
                        RPC_INVALID_PARAMETER,
                        "Parameter 'txids' cannot be empty".into(),
                    )),
                );
            }
            let mut set: std::collections::BTreeSet<Txid> = Default::default();
            for tv in txids_v {
                let Some(s) = tv.as_str() else {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, field_type_message(tv, "string"))),
                    );
                };
                let txid = match parse_hash_v::<Txid>(s, "txid") {
                    Ok(t) => t,
                    Err(e) => return (Value::Null, Some(e)),
                };
                if !set.insert(txid) {
                    return (
                        Value::Null,
                        Some((
                            RPC_INVALID_PARAMETER,
                            format!("Invalid parameter, duplicated txid: {s}"),
                        )),
                    );
                }
            }
            let sel_hash = match arr.get(1) {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => match parse_hash_v::<BlockHash>(s, "blockhash") {
                    Ok(h) => Some(h),
                    Err(e) => return (Value::Null, Some(e)),
                },
                Some(v) => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(2, "blockhash", v, "string"),
                        )),
                    );
                }
            };
            let prove_witness = match arr.get(2) {
                None | Some(Value::Null) => false,
                Some(Value::Object(o)) => match o.get("prove_witness") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(b)) => *b,
                    Some(v) => {
                        return (
                            Value::Null,
                            Some((RPC_TYPE_ERROR, field_type_message(v, "bool"))),
                        );
                    }
                },
                Some(v) => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(3, "options", v, "object"),
                        )),
                    );
                }
            };
            chain_query(queries, move |cs, _| {
                // Block selection — Core: explicit hash, else the first
                // txid with an unspent vout 0 (AccessByTxid), else the
                // txindex's containing block.
                let node = if let Some(h) = sel_hash {
                    *cs.tree()
                        .get(&h)
                        .ok_or((RPC_INVALID_ADDRESS_OR_KEY, "Block not found".to_string()))?
                } else {
                    let mut found = None;
                    for txid in &set {
                        let op = OutPoint {
                            txid: *txid,
                            vout: 0,
                        };
                        if let Some(coin) = cs.utxo().get(&op)
                            && let Some(bh) = cs.chain().get(coin.height as usize)
                            && let Some(n) = cs.tree().get(bh)
                        {
                            found = Some(*n);
                            break;
                        }
                    }
                    if found.is_none()
                        && let Some(first) = set.iter().next()
                        && let Some(bh) = cs.find_transaction(first)
                    {
                        found = cs.tree().get(&bh).copied();
                    }
                    let Some(n) = found else {
                        return Err((
                            RPC_INVALID_ADDRESS_OR_KEY,
                            "Transaction not yet in block".to_string(),
                        ));
                    };
                    n
                };
                let hash = node.hash();
                let Some(block) = cs.body(&hash) else {
                    return Err((RPC_INTERNAL_ERROR, "Can't read block from disk".into()));
                };
                let mut found = Vec::new();
                for (i, tx) in block.transactions.iter().enumerate() {
                    if set.contains(&tx.txid()) {
                        found.push((i, tx));
                    }
                }
                if found.len() != set.len() {
                    return Err((
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Not all transactions found in specified or retrieved block".into(),
                    ));
                }
                let txids: Vec<[u8; 32]> = block
                    .transactions
                    .iter()
                    .map(|tx| tx.txid().to_bytes())
                    .collect();
                let mut matches: Vec<bool> = block
                    .transactions
                    .iter()
                    .map(|tx| set.contains(&tx.txid()))
                    .collect();
                let mut out = Vec::new();
                if prove_witness {
                    let gentx = &block.transactions[0];
                    let has_commitment = block.witness_commitment_output().is_some();
                    let mut wtxid_tree = None;
                    let prove_gentx = matches[0];
                    if has_commitment {
                        // wtxid tree: null placeholder for gentx, then
                        // each tx's witness hash.
                        let mut wtxids = Vec::with_capacity(txids.len());
                        wtxids.push([0u8; 32]);
                        for tx in &block.transactions[1..] {
                            wtxids.push(tx.wtxid().to_bytes());
                        }
                        wtxid_tree = Some(avila_consensus::merkle::PartialMerkleTree::build(
                            &wtxids, &matches,
                        ));
                        for m in matches.iter_mut() {
                            *m = false;
                        }
                    }
                    // The gentx is always proven in the txid tree.
                    matches[0] = true;
                    let txn = avila_consensus::merkle::PartialMerkleTree::build(&txids, &matches);
                    let version: i32 = if wtxid_tree.is_some() { -2 } else { -1 };
                    out.extend_from_slice(&version.to_le_bytes());
                    out.extend_from_slice(&block.header.encode());
                    txn.encode(&mut out);
                    out.extend_from_slice(&gentx.encode());
                    if let Some(wt) = &wtxid_tree {
                        wt.encode(&mut out);
                    } else {
                        out.push(u8::from(prove_gentx));
                    }
                    let txs: Vec<Value> = found
                        .iter()
                        .map(|(i, tx)| {
                            json!({
                                "txid": tx.txid().to_string(),
                                "wtxid": tx.wtxid().to_string(),
                                "blockindex": i,
                            })
                        })
                        .collect();
                    Ok(json!({
                        "proof": hex::encode(&out),
                        "proven": {
                            "blockhash": hash.to_string(),
                            "blockheight": node.height,
                            "tx": txs,
                        },
                    }))
                } else {
                    let txn = avila_consensus::merkle::PartialMerkleTree::build(&txids, &matches);
                    out.extend_from_slice(&block.header.encode());
                    txn.encode(&mut out);
                    Ok(json!(hex::encode(&out)))
                }
            })
        }
        "verifytxoutproof" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.is_empty() || arr.len() > 2 {
                return help_error(VERIFYTXOUTPROOF_HELP);
            }
            let proof_hex = match &arr[0] {
                Value::String(s) => s.clone(),
                v => {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(1, "proof", v, "string"))),
                    );
                }
            };
            let verify_witness = match arr.get(1) {
                None | Some(Value::Null) => false,
                Some(Value::Object(o)) => match o.get("verify_witness") {
                    None | Some(Value::Null) => false,
                    Some(Value::Bool(b)) => *b,
                    Some(v) => {
                        return (
                            Value::Null,
                            Some((RPC_TYPE_ERROR, field_type_message(v, "bool"))),
                        );
                    }
                },
                Some(v) => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(2, "options", v, "object"),
                        )),
                    );
                }
            };
            let bytes = match hex::decode(&proof_hex) {
                Ok(b) => b,
                Err(_) => {
                    return (
                        Value::Null,
                        Some((
                            RPC_INVALID_PARAMETER,
                            format!("proof must be hexadecimal string (not '{proof_hex}')"),
                        )),
                    );
                }
            };
            chain_query(queries, move |cs, _| {
                let mut d = avila_consensus::encode::Decoder::new(&bytes);
                // Classic: header ‖ txn. Witness form: i32 version
                // (-2/-1) ‖ header ‖ txn ‖ gentx ‖ (wtxid_tree | bool).
                let mut version: Option<i32> = None;
                let header = if verify_witness {
                    match d.read_i32_le() {
                        Ok(v) => version = Some(v),
                        Err(_) => {
                            return Err((
                                RPC_MISC_ERROR,
                                "DataStream::read(): end of data: iostream error".into(),
                            ));
                        }
                    }
                    match BlockHeader::read(&mut d) {
                        Ok(h) => h,
                        Err(_) => {
                            return Err((
                                RPC_MISC_ERROR,
                                "DataStream::read(): end of data: iostream error".into(),
                            ));
                        }
                    }
                } else {
                    match BlockHeader::read(&mut d) {
                        Ok(h) => h,
                        Err(_) => {
                            return Err((
                                RPC_MISC_ERROR,
                                "DataStream::read(): end of data: iostream error".into(),
                            ));
                        }
                    }
                };
                let mut txn = match avila_consensus::merkle::PartialMerkleTree::decode(&mut d) {
                    Some(t) => t,
                    None => {
                        return Err((
                            RPC_MISC_ERROR,
                            "DataStream::read(): end of data: iostream error".into(),
                        ));
                    }
                };
                // Witness tail: gentx + (wtxid tree | prove_gentx flag).
                let mut gentx: Option<Transaction> = None;
                let mut prove_gentx = false;
                let mut wtxid_tree = None;
                if verify_witness {
                    gentx = match Transaction::read(&mut d) {
                        Ok(t) => Some(t),
                        Err(_) => {
                            return Err((
                                RPC_MISC_ERROR,
                                "DataStream::read(): end of data: iostream error".into(),
                            ));
                        }
                    };
                    match version {
                        Some(-1) => match d.read_u8() {
                            Ok(b) => prove_gentx = b != 0,
                            Err(_) => {
                                return Err((
                                    RPC_MISC_ERROR,
                                    "DataStream::read(): end of data: iostream error".into(),
                                ));
                            }
                        },
                        _ => {
                            wtxid_tree = Some(
                                match avila_consensus::merkle::PartialMerkleTree::decode(&mut d) {
                                    Some(t) => t,
                                    None => {
                                        return Err((
                                            RPC_MISC_ERROR,
                                            "DataStream::read(): end of data: iostream error"
                                                .into(),
                                        ));
                                    }
                                },
                            );
                        }
                    }
                }
                // ExtractMatches must reproduce the header's merkle root.
                let Some((root, mut matches)) = txn.extract() else {
                    return Ok(if verify_witness { json!({}) } else { json!([]) });
                };
                if root != header.merkle_root.to_bytes() || matches.is_empty() {
                    return Ok(if verify_witness { json!({}) } else { json!([]) });
                }
                if verify_witness {
                    // The gentx must be proven at index 0 and present.
                    let Some(first) = matches.first().copied() else {
                        return Ok(json!({}));
                    };
                    if first.1 != 0 {
                        return Ok(json!({}));
                    }
                    let Some(gx) = &gentx else {
                        return Ok(json!({}));
                    };
                    if gx.txid().to_bytes() != first.0 || !gx.is_coinbase() {
                        return Ok(json!({}));
                    }
                    // If the gentx carries a witness commitment, verify
                    // the wtxid tree against it.
                    let commit_idx = gx.outputs.iter().rposition(|o| {
                        let s = o.script_pubkey.as_bytes();
                        s.len() >= 38 && s[..6] == [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]
                    });
                    match commit_idx {
                        None => {
                            // No commitment: gentx only proves itself
                            // when prove_gentx asked for it.
                            if !prove_gentx {
                                matches.remove(0);
                            }
                        }
                        Some(ci) => {
                            let Some(wt) = wtxid_tree else {
                                return Ok(json!({}));
                            };
                            let mut wt2 = wt;
                            let Some((wroot, mut wmatch)) = wt2.extract() else {
                                return Ok(json!({}));
                            };
                            if wmatch.is_empty() {
                                return Ok(json!({}));
                            }
                            // wtxid_root ‖ reserved → sha256d must equal
                            // the commitment's 32-byte payload.
                            let witness = &gx.inputs[0].witness;
                            let items = witness.items();
                            if items.len() != 1 || items[0].len() != 32 {
                                return Ok(json!({}));
                            }
                            let mut buf = Vec::with_capacity(64);
                            buf.extend_from_slice(&wroot);
                            buf.extend_from_slice(&items[0]);
                            let commit = avila_consensus::hash::sha256d(&buf);
                            let spk = gx.outputs[ci].script_pubkey.as_bytes();
                            if commit != spk[6..38] {
                                return Ok(json!({}));
                            }
                            // A gentx "match" at wtxid index 0 is the
                            // null placeholder → report its txid.
                            if wmatch[0].1 == 0 {
                                if wmatch[0].0 != [0u8; 32] {
                                    return Ok(json!({}));
                                }
                                wmatch[0].0 = gx.txid().to_bytes();
                            }
                            matches = wmatch;
                        }
                    }
                }
                // The block must be on the active chain with a known
                // tx count matching the proof's claim.
                let block_hash = header.hash();
                let Some(bnode) = cs.tree().get(&block_hash) else {
                    return Err((
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Block not found in chain".to_string(),
                    ));
                };
                if cs.chain().get(bnode.height as usize) != Some(&block_hash) {
                    return Err((
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Block not found in chain".to_string(),
                    ));
                }
                // pindex->nTx==0 (no body) is part of Knots' "not in
                // chain" predicate; a count mismatch is an empty result.
                let n_tx = match cs.body(&block_hash) {
                    Some(b) => b.transactions.len() as u32,
                    None => {
                        return Err((
                            RPC_INVALID_ADDRESS_OR_KEY,
                            "Block not found in chain".to_string(),
                        ));
                    }
                };
                if n_tx != txn.num_transactions {
                    return Ok(if verify_witness { json!({}) } else { json!([]) });
                }
                if !verify_witness {
                    return Ok(json!(
                        matches
                            .iter()
                            .map(|(h, _)| Txid::from_bytes(*h).to_string())
                            .collect::<Vec<_>>()
                    ));
                }
                let tip_h = cs.chain().len() as u32 - 1;
                Ok(json!({
                    "blockheight": bnode.height,
                    "confirmations": tip_h - bnode.height + 1,
                    "blockhash": block_hash.to_string(),
                    "tx": matches
                        .iter()
                        .map(|(h, i)| json!({
                            "wtxid": Txid::from_bytes(*h).to_string(),
                            "blockindex": i,
                        }))
                        .collect::<Vec<_>>(),
                }))
            })
        }
        "getindexinfo" => {
            if params.as_array().is_some_and(|a| a.len() > 1) {
                return help_error(GETINDEXINFO_HELP);
            }
            let filter = match param(params, 0, "index_name") {
                Some(v) if !v.is_null() && !v.is_string() => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(1, "index_name", v, "string"),
                        )),
                    );
                }
                Some(v) if !v.is_null() => Some(v.as_str().unwrap_or_default().to_string()),
                _ => None,
            };
            chain_query(queries, move |cs, _| {
                if !cs.txindex_enabled() || filter.as_deref().is_some_and(|f| f != "txindex") {
                    return Ok(json!({}));
                }
                Ok(json!({
                    "txindex": {
                        "synced": true,
                        "best_block_height": cs.chain().len() as u32 - 1,
                    }
                }))
            })
        }
        "getrawtransaction" => {
            let Some(txid) = param(params, 0, "txid")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<Txid>().ok())
            else {
                return missing_params("txid");
            };
            // Core accepts verbosity as a bool or 0/1/2 int.
            let verbosity = param(params, 1, "verbose")
                .map(|v| {
                    v.as_u64()
                        .or_else(|| v.as_bool().map(u64::from))
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            let block_hash = param(params, 2, "blockhash")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<BlockHash>().ok());
            chain_query(queries, move |cs, mgr| {
                // Core's lookup order: mempool first, then the named
                // block or the txindex; a plain txid without either is
                // the documented -5. The genesis coinbase is refused on
                // every path — it predates the txindex contract.
                if cs
                    .tree()
                    .params()
                    .genesis_block()
                    .is_some_and(|g| g.transactions[0].txid() == txid)
                {
                    return Err((
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "The genesis block coinbase is not considered an \
                         ordinary transaction and cannot be retrieved"
                            .into(),
                    ));
                }
                let mut via_index = false;
                let found = if let Some(bh) = block_hash {
                    cs.body(&bh).and_then(|block| {
                        block
                            .transactions
                            .iter()
                            .find(|tx| tx.txid() == txid)
                            .cloned()
                            .map(|tx| (tx, Some(bh)))
                    })
                } else if let Some(tx) = mgr.mempool_ref().get(&txid) {
                    Some((tx.clone(), None))
                } else {
                    via_index = true;
                    cs.find_transaction(&txid).and_then(|bh| {
                        cs.body(&bh).and_then(|block| {
                            block
                                .transactions
                                .iter()
                                .find(|tx| tx.txid() == txid)
                                .cloned()
                                .map(|tx| (tx, Some(bh)))
                        })
                    })
                };
                let Some((tx, in_block)) = found else {
                    return Err((
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "No such mempool transaction. Use -txindex or provide a \
                         block hash to enable blockchain transaction queries. \
                         Use gettransaction for wallet transactions."
                            .into(),
                    ));
                };
                match verbosity {
                    0 => Ok(json!(hex::encode(&tx.encode()))),
                    1 | 2 => {
                        let mut out = tx_json(&tx, cs.tree().params(), true);
                        if let Some(bh) = in_block
                            && let Some(node) = cs.tree().get(&bh)
                        {
                            out["blockhash"] = json!(bh.to_string());
                            out["blocktime"] = json!(node.header.time);
                            out["time"] = json!(node.header.time);
                            // `in_active_chain` is emitted on the index
                            // path only (Core's convention — a named
                            // block is by definition where the caller
                            // looked); confirmations count only for
                            // active-chain blocks.
                            let active = !via_index || cs.on_active_chain(&bh);
                            if via_index {
                                out["in_active_chain"] = json!(active);
                            }
                            if active {
                                let tip = cs.tree().tip().height;
                                out["confirmations"] = json!(i64::from(tip - node.height) + 1);
                            }
                        }
                        Ok(out)
                    }
                    _ => Err((
                        RPC_INVALID_PARAMS,
                        format!("unsupported verbosity {verbosity} — 0, 1 and 2 are implemented"),
                    )),
                }
            })
        }
        // Core's savemempool — writes mempool.dat under the chainstate
        // dir and returns its path; without a store there is nowhere
        // persistent to write, which is an honest -1 misc error.
        "savemempool" => chain_query(queries, |_cs, mgr| {
            let Some(store) = _cs.store() else {
                return Err((RPC_MISC_ERROR, "no data directory configured".into()));
            };
            let path = store.dir().join("mempool.dat");
            match mgr.mempool_ref().save(&path) {
                // Core reports the absolute path of the written file.
                Ok(_) => Ok(json!({
                    "filename": std::fs::canonicalize(&path)
                        .unwrap_or(path)
                        .to_string_lossy()
                })),
                Err(e) => Err((RPC_MISC_ERROR, format!("save mempool: {e}"))),
            }
        }),
        "getpeerinfo" => chain_query(queries, |cs, mgr| {
            Ok(Value::Array(
                mgr.peer_snapshots()
                    .iter()
                    .map(|p| {
                        // Core-named fields where we hold the data;
                        // ours are kept alongside so the claims-vs-
                        // served framing stays visible. Per-command
                        // histograms and timers come from the wire
                        // layer's own counters.
                        let mut peer = json!({
                            "id": p.id,
                            "addr": p.remote.map(|a| a.to_string()),
                            "network": p.remote.map(|a| {
                                if a.is_ipv4() { "ipv4" } else { "ipv6" }
                            }),
                            "inbound": p.inbound,
                            "connection_type": if p.inbound {
                                "inbound"
                            } else {
                                "outbound-full-relay"
                            },
                            // v2 transport (BIP324) is not implemented.
                            "transport_protocol_type": "v1",
                            "session_id": format!("{:016x}", p.telemetry.session_id),
                            "version": p.version,
                            // Core's field name is `subver` — there is
                            // no `subversion` in getpeerinfo.
                            "subver": p.user_agent,
                            "services": p.services.map(|s| format!("{s:016x}")),
                            "servicesnames": p.services.map(service_names),
                            "relaytxes": p.relay,
                            "addr_relay_enabled": p.relay.unwrap_or(false),
                            "startingheight": p.start_height,
                            "claimed_height": p.start_height,
                            // Heights of the last header/block this peer
                            // gave us — Core's semantics, not counts.
                            "synced_headers": p.synced_header_height,
                            "synced_blocks": p.synced_block_height,
                            "presynced_headers": false,
                            "handshake": p.established,
                            "headers_received": p.headers_received,
                            "blocks_received": p.blocks_received,
                            "in_flight": p.in_flight,
                            "inflight": p
                                .in_flight_hashes
                                .iter()
                                .filter_map(|h| {
                                    cs.tree().get(h).map(|n| n.height)
                                })
                                .collect::<Vec<_>>(),
                            "conntime": p.telemetry.connected,
                            "connected_secs": p.connected_secs,
                            "bytessent": p.telemetry.bytes_sent,
                            "bytesrecv": p.telemetry.bytes_recv,
                            "bytessent_per_msg": p.telemetry.sent_by_msg,
                            "bytesrecv_per_msg": p.telemetry.recv_by_msg,
                            "lastsend": p.telemetry.last_send,
                            "lastrecv": p.telemetry.last_recv,
                            "timeoffset": 0,
                            "misbehavior_score": 0,
                            "permissions": [],
                            // We never send feefilter — the peer applies
                            // its own default floor.
                            "minfeefilter": 0,
                            // Compact-block high-bandwidth mode was never
                            // negotiated.
                            "bip152_hb_to": false,
                            "bip152_hb_from": false,
                            "addr_processed": p.addr_processed,
                            "addr_rate_limited": p.addr_rate_limited,
                            "idle_secs": p.idle_secs,
                        });
                        // Core omits timing fields until the events
                        // exist — no ping answer yet, no block, no tx.
                        if p.last_announce > 0 {
                            peer["lastannounce"] = json!(p.last_announce);
                        }
                        if p.last_block_time > 0 {
                            peer["last_block"] = json!(p.last_block_time);
                        }
                        if p.last_tx_time > 0 {
                            peer["last_transaction"] = json!(p.last_tx_time);
                        }
                        if let Some(t) = p.ping_last_secs {
                            peer["pingtime"] = json!(t);
                        }
                        if let Some(t) = p.ping_min_secs {
                            peer["minping"] = json!(t);
                        }
                        if let Some(t) = p.ping_wait_secs {
                            peer["pingwait"] = json!(t);
                        }
                        peer
                    })
                    .collect(),
            ))
        }),
        "getmempoolinfo" => chain_query(queries, |_, mgr| {
            let pool = mgr.mempool_ref();
            let bytes = pool.total_tx_bytes();
            // BTC-denominated fields like Core's: our counters are
            // satoshis, so convert.
            let sat_to_btc = |sat_per_kvb: i64| sat_per_kvb as f64 / 100_000_000.0;
            let relay_btc = sat_to_btc(pool.min_relay_fee());
            Ok(json!({
                "loaded": true,
                "size": pool.len(),
                "bytes": bytes,
                // Encoded size is the honest floor for Core's
                // allocator-dependent DynamicUsage figure.
                "usage": bytes,
                "total_fee": pool.total_fees() as f64 / 100_000_000.0,
                "maxmempool": pool.max_bytes(),
                // No size-based decay yet — the dynamic floor equals
                // the configured relay floor until that lands.
                "mempoolminfee": relay_btc,
                "minrelaytxfee": relay_btc,
                "incrementalrelayfee": sat_to_btc(avila_mempool::INCREMENTAL_RELAY_FEE),
                // Full-RBF matches deployed Core's -mempoolfullrbf=1:
                // replacements no longer need BIP125 signaling.
                "fullrbf": pool.full_rbf(),
                "unbroadcastcount": pool.unbroadcast_count(),
            }))
        }),
        "getchaintips" => chain_query(queries, |cs, _| {
            // A tip is an indexed node no other node points at as
            // parent — the same shape Core's setBlockIndexCandidates
            // walk produces.
            let parents: std::collections::HashSet<BlockHash> = cs
                .tree()
                .nodes()
                .map(|(_, n)| n.header.prev_block_hash)
                .collect();
            let tip_height = cs.tree().tip().height;
            let mut tips: Vec<Value> = cs
                .tree()
                .nodes()
                .filter(|(hash, _)| !parents.contains(*hash))
                .map(|(hash, node)| {
                    // branchlen: blocks between this tip and its fork
                    // point on the active chain (0 when it IS the tip).
                    let mut branchlen = 0u32;
                    if *hash != cs.tip_hash() {
                        for h in (0..=node.height.min(tip_height)).rev() {
                            let on_active = cs
                                .tree()
                                .get_ancestor(hash, h)
                                .is_some_and(|a| cs.chain().get(h as usize) == Some(&a.hash()));
                            if on_active {
                                break;
                            }
                            branchlen = node.height - h;
                        }
                    }
                    let status = if *hash == cs.tip_hash() {
                        "active"
                    } else if cs.tree().is_failed(hash) {
                        "invalid"
                    } else if cs.have_body(hash) {
                        "valid-fork"
                    } else {
                        "headers-only"
                    };
                    json!({
                        "height": node.height,
                        "hash": hash.to_string(),
                        "branchlen": branchlen,
                        "status": status,
                    })
                })
                .collect();
            tips.sort_by_key(|t| std::cmp::Reverse(t["height"].as_u64().unwrap_or(0)));
            Ok(json!(tips))
        }),
        "getrawmempool" => {
            let verbose = param(params, 0, "verbose")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            chain_query(queries, move |_, mgr| {
                let pool = mgr.mempool_ref();
                if verbose {
                    let map: serde_json::Map<String, Value> = pool
                        .txids()
                        .iter()
                        .filter_map(|txid| {
                            pool.entry(txid)
                                .map(|e| (txid.to_string(), entry_json(pool, txid, e)))
                        })
                        .collect();
                    Ok(Value::Object(map))
                } else {
                    Ok(json!(
                        pool.txids()
                            .iter()
                            .map(|t| t.to_string())
                            .collect::<Vec<_>>()
                    ))
                }
            })
        }
        "getmempoolentry" | "getmempoolancestors" | "getmempooldescendants" => {
            let Some(txid) = param(params, 0, "txid")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<Txid>().ok())
            else {
                return missing_params("txid");
            };
            let verbose = param(params, 1, "verbose")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            // `method` borrows the request — own it for the 'static closure.
            let which = method.to_string();
            chain_query(queries, move |_, mgr| {
                let pool = mgr.mempool_ref();
                let Some(entry) = pool.entry(&txid) else {
                    return Err((
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Transaction not in mempool".into(),
                    ));
                };
                match which.as_str() {
                    "getmempoolentry" => Ok(entry_json(pool, &txid, entry)),
                    "getmempoolancestors" => {
                        Ok(family_json(pool, pool.ancestor_txids(&entry.tx), verbose))
                    }
                    _ => Ok(family_json(pool, pool.descendant_txids(&txid), verbose)),
                }
            })
        }
        "testmempoolaccept" => {
            // Core's signature is `testmempoolaccept [rawtxs]` — the
            // first positional param is the array (a bare string is a
            // lenient single-tx shorthand).
            let raws: Vec<String> = match param(params, 0, "rawtxs") {
                Some(Value::Array(items)) => items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                Some(Value::String(s)) => vec![s.clone()],
                _ => Vec::new(),
            };
            if raws.is_empty() {
                return missing_params("rawtxs");
            }
            chain_query(queries, move |cs, mgr| {
                let mut out = Vec::with_capacity(raws.len());
                for raw in raws {
                    let Ok(bytes) = hex::decode(&raw) else {
                        return Err((RPC_INVALID_PARAMS, "rawtx is not valid hex".into()));
                    };
                    let tx = match Transaction::decode(&bytes) {
                        Ok(tx) => tx,
                        Err(e) => {
                            return Err((RPC_INVALID_PARAMS, format!("TX decode failed: {e}")));
                        }
                    };
                    let pool = mgr.mempool_ref();
                    let steps = pool.explain_tx(&tx, cs, 0);
                    let allowed = steps.iter().all(|s| s.passed);
                    let mut verdict = json!({
                        "txid": tx.txid().to_string(),
                        "wtxid": tx.wtxid().to_string(),
                        "allowed": allowed,
                        "vsize": tx.weight().div_ceil(4),
                    });
                    if allowed {
                        // Admission passed every gate — report the fee
                        // the inputs resolve to (Core's fees.base).
                        let input_sum: i64 = tx
                            .inputs
                            .iter()
                            .filter_map(|i| pool.resolve(cs, &i.previous_output))
                            .map(|c| c.out.value)
                            .sum();
                        let output_sum: i64 = tx.outputs.iter().map(|o| o.value).sum();
                        let fee = input_sum - output_sum;
                        verdict["fees"] = json!({"base": fee as f64 / 100_000_000.0});
                        verdict["package-feerrate"] =
                            json!(fee as f64 / tx.weight().div_ceil(4).max(1) as f64 / 1000.0);
                    } else if let Some(failed) = steps.iter().find(|s| !s.passed) {
                        verdict["reject-reason"] = json!(failed.detail);
                    }
                    // The full gate trace rides along — our extension,
                    // clearly marked, for "why was this rejected".
                    verdict["avila_policy_trace"] =
                        json!(steps
                        .iter()
                        .map(|s| json!({"gate": s.gate, "passed": s.passed, "detail": s.detail}))
                        .collect::<Vec<_>>());
                    out.push(verdict);
                }
                Ok(json!(out))
            })
        }
        "sendrawtransaction" => {
            let Some(raw) = param(params, 0, "hexstring").and_then(Value::as_str) else {
                return missing_params("hexstring");
            };
            let maxfeerate = param(params, 1, "maxfeerate")
                .and_then(Value::as_f64)
                .unwrap_or(DEFAULT_MAX_RAW_TX_FEE_RATE);
            if maxfeerate < 0.0 {
                return (
                    Value::Null,
                    Some((
                        RPC_INVALID_PARAMETER,
                        "Invalid parameter, maxfeerate cannot be negative".into(),
                    )),
                );
            }
            let maxburnamount = param(params, 2, "maxburnamount")
                .and_then(Value::as_f64)
                .unwrap_or(0.0);
            let Ok(bytes) = hex::decode(raw) else {
                return (
                    Value::Null,
                    Some((RPC_DESERIALIZATION_ERROR, "TX decode failed".into())),
                );
            };
            chain_query(queries, move |cs, mgr| {
                let tx = match Transaction::decode(&bytes) {
                    Ok(tx) => tx,
                    Err(e) => {
                        return Err((RPC_DESERIALIZATION_ERROR, format!("TX decode failed: {e}")));
                    }
                };
                let txid = tx.txid();
                let wtxid = tx.wtxid();
                let pool = mgr.mempool_ref();
                // Core's BroadcastTransaction: an already-pooled txid is
                // a silent success — resubmitting is idempotent.
                if pool.entry(&txid).is_some() {
                    return Ok(json!(txid.to_string()));
                }
                // Core's BroadcastTransaction policy bounds: the caller's
                // maxfeerate (BTC/kvB; 0 = unlimited) and maxburnamount
                // (BTC) gates run before admission.
                let input_sum: Option<i64> = tx
                    .inputs
                    .iter()
                    .map(|i| pool.resolve(cs, &i.previous_output).map(|c| c.out.value))
                    .sum();
                if maxfeerate > 0.0
                    && let Some(input_sum) = input_sum
                {
                    let output_sum: i64 = tx.outputs.iter().map(|o| o.value).sum();
                    let fee = input_sum - output_sum;
                    let vsize = tx.weight().div_ceil(4).max(1);
                    // Core: max_tx_fee = maxfeerate.GetFee(vsize) — an
                    // absolute sats bound derived from the rate.
                    let max_tx_fee = (maxfeerate * 100_000_000.0 * vsize as f64 / 1000.0) as i64;
                    if fee > max_tx_fee {
                        return Err((
                            RPC_VERIFY_ERROR,
                            "Fee exceeds maximum configured by user \
                             (e.g. -maxtxfee, maxfeerate)"
                                .into(),
                        ));
                    }
                }
                let burned: i64 = tx
                    .outputs
                    .iter()
                    .filter(|o| o.script_pubkey.is_unspendable())
                    .map(|o| o.value)
                    .sum();
                let max_burn_sat = (maxburnamount * 100_000_000.0) as i64;
                if burned > max_burn_sat {
                    return Err((
                        RPC_VERIFY_ERROR,
                        "Unspendable output exceeds maximum configured by user \
                         (maxburnamount)"
                            .into(),
                    ));
                }
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                match mgr.mempool().accept_tx(tx, cs, now) {
                    Ok(_) => {
                        // Admitted — relay an inv to every tx-accepting
                        // peer (Core's RelayTransaction path) and track
                        // it as unbroadcast until a peer's getdata
                        // acknowledges the announcement.
                        mgr.mempool().mark_unbroadcast(&txid);
                        mgr.announce_tx(txid, wtxid);
                        Ok(json!(txid.to_string()))
                    }
                    Err(avila_mempool::MempoolReject::AlreadyKnown) => {
                        mgr.mempool().mark_unbroadcast(&txid);
                        Ok(json!(txid.to_string()))
                    }
                    // Consensus and input failures carry Core's
                    // state.Invalid reason strings via `reason()`;
                    // policy rejects already Display as Core strings.
                    Err(reject) => Err((
                        RPC_VERIFY_REJECTED,
                        match &reject {
                            avila_mempool::MempoolReject::Consensus(e) => e.reason().to_string(),
                            avila_mempool::MempoolReject::Inputs(e) => e.reason().into_owned(),
                            _ => reject.to_string(),
                        },
                    )),
                }
            })
        }
        "getblockfrompeer" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() != 2 {
                return help_error(GETBLOCKFROMPEER_HELP);
            }
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if !arr[0].is_string() {
                type_errors.push((1, "blockhash", &arr[0], "string"));
            }
            if !arr[1].is_number() {
                type_errors.push((2, "peer_id", &arr[1], "number"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            // Core's body order: ParseHashV → getInt<int64> → header
            // index → already-downloaded → peer → schedule.
            let hash: BlockHash =
                match parse_hash_v(arr[0].as_str().unwrap_or_default(), "blockhash") {
                    Ok(h) => h,
                    Err(e) => return (Value::Null, Some(e)),
                };
            let Some(peer_id) = arr[1].as_i64() else {
                return (
                    Value::Null,
                    Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                );
            };
            chain_query(queries, move |cs, mgr| {
                if !cs.tree().contains(&hash) {
                    return Err((RPC_MISC_ERROR, "Block header missing".into()));
                }
                if cs.body(&hash).is_some() {
                    return Err((RPC_MISC_ERROR, "Block already downloaded".into()));
                }
                // Core's NodeId is signed — a negative id can't name a
                // peer, so it lands in "does not exist" like Core.
                let peer_id = peer_id as u64;
                if !mgr.peer_ids().contains(&peer_id) {
                    return Err((RPC_MISC_ERROR, "Peer does not exist".into()));
                }
                if !mgr.fetch_block(peer_id, hash) {
                    return Err((RPC_MISC_ERROR, "Failed to fetch block from peer".into()));
                }
                Ok(json!({}))
            })
        }
        "waitforblock" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.is_empty() || arr.len() > 2 {
                return help_error(WAITFORBLOCK_HELP);
            }
            // RPCHelpMan type pass — every bad argument collected.
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if !arr[0].is_string() {
                type_errors.push((1, "blockhash", &arr[0], "string"));
            }
            if arr.len() == 2 && !(arr[1].is_number() || arr[1].is_null()) {
                type_errors.push((2, "timeout", &arr[1], "number"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            // Body order: ParseHashV the hash, then the timeout int.
            let hash: BlockHash =
                match parse_hash_v(arr[0].as_str().unwrap_or_default(), "blockhash") {
                    Ok(h) => h,
                    Err(e) => return (Value::Null, Some(e)),
                };
            let timeout = match wait_timeout_ms(arr.get(1)) {
                Ok(t) => t,
                Err(e) => return (Value::Null, Some(e)),
            };
            // Core fires when the block gains BLOCK_HAVE_DATA — body in
            // the store or the parked map, connected or not.
            block_wait(queries, waiters, timeout, move |cs| cs.have_body(&hash))
        }
        "waitforblockheight" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.is_empty() || arr.len() > 2 {
                return help_error(WAITFORBLOCKHEIGHT_HELP);
            }
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if !arr[0].is_number() {
                type_errors.push((1, "height", &arr[0], "number"));
            }
            if arr.len() == 2 && !(arr[1].is_number() || arr[1].is_null()) {
                type_errors.push((2, "timeout", &arr[1], "number"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            // Height is Core's getInt<int> — non-integral and
            // out-of-i32 both land in the integer-range error. A height
            // already reached (negatives included) returns instantly.
            let Some(height) = arr[0].as_i64().and_then(|h| i32::try_from(h).ok()) else {
                return (
                    Value::Null,
                    Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                );
            };
            let timeout = match wait_timeout_ms(arr.get(1)) {
                Ok(t) => t,
                Err(e) => return (Value::Null, Some(e)),
            };
            block_wait(queries, waiters, timeout, move |cs| {
                cs.chain().len() as i64 > height as i64
            })
        }
        "waitfornewblock" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() > 1 {
                return help_error(WAITFORNEWBLOCK_HELP);
            }
            if let Some(timeout) = arr.first()
                && !(timeout.is_number() || timeout.is_null())
            {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(1, "timeout", timeout, "number"),
                    )),
                );
            }
            let timeout = match wait_timeout_ms(arr.first()) {
                Ok(t) => t,
                Err(e) => return (Value::Null, Some(e)),
            };
            // The tip the call started from — Core's `block` snapshot at
            // WaitStart; the waiter fires on the first *different* tip.
            let (start, start_err) = chain_query(queries, |cs, _| Ok(wait_tip_result(cs)));
            if let Some(err) = start_err {
                return (Value::Null, Some(err));
            }
            let start_hash = start
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            block_wait(queries, waiters, timeout, move |cs| {
                cs.chain().last().map(ToString::to_string).as_deref() != Some(start_hash.as_str())
            })
        }
        // Core's createrawtransaction — pure construction (no signing,
        // no wallet, no broadcast), following `ConstructTransaction`
        // in rpc/rawtransaction_util.cpp step for step.
        "createrawtransaction" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() < 2 || arr.len() > 4 {
                return help_error(CREATERAWTRANSACTION_HELP);
            }
            // RPCHelpMan type pass. `outputs` is declared VARR|VOBJ —
            // a union Core's check skips at this layer (the body's
            // NormalizeOutputs rejects scalars itself).
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if !arr[0].is_array() {
                type_errors.push((1, "inputs", &arr[0], "array"));
            }
            if let Some(locktime) = arr.get(2)
                && !(locktime.is_number() || locktime.is_null())
            {
                type_errors.push((3, "locktime", locktime, "number"));
            }
            if let Some(replaceable) = arr.get(3)
                && !(replaceable.is_boolean() || replaceable.is_null())
            {
                type_errors.push((4, "replaceable", replaceable, "bool"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            // Body order: locktime parses before any input field.
            let locktime = match arr.get(2) {
                None | Some(Value::Null) => 0u32,
                Some(v) => {
                    let Some(n) = v.as_i64() else {
                        return (
                            Value::Null,
                            Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                        );
                    };
                    if !(0..=u32::MAX as i64).contains(&n) {
                        return (
                            Value::Null,
                            Some((
                                RPC_INVALID_PARAMETER,
                                "Invalid parameter, locktime out of range".into(),
                            )),
                        );
                    }
                    n as u32
                }
            };
            let rbf: Option<bool> = arr.get(3).and_then(Value::as_bool);
            let inputs = arr[0].clone();
            let outputs = arr[1].clone();
            chain_query(queries, move |cs, _| {
                let params = cs.tree().params();
                // AddInputs — per element: object check, ParseHashO
                // txid, vout num/i32/non-negative, then the sequence
                // default and any explicit override.
                let default_seq = if rbf.unwrap_or(true) {
                    0xffff_fffd // MAX_BIP125_RBF_SEQUENCE
                } else if locktime != 0 {
                    0xffff_fffe // CTxIn::MAX_SEQUENCE_NONFINAL
                } else {
                    0xffff_ffff // CTxIn::SEQUENCE_FINAL
                };
                let mut txins = Vec::new();
                for input in inputs.as_array().map(Vec::as_slice).unwrap_or(&[]) {
                    let Some(obj) = input.as_object() else {
                        return Err((RPC_TYPE_ERROR, field_type_message(input, "object")));
                    };
                    let txid_v = obj.get("txid").unwrap_or(&Value::Null);
                    let Some(txid_s) = txid_v.as_str() else {
                        return Err((RPC_TYPE_ERROR, field_type_message(txid_v, "string")));
                    };
                    let txid: Txid = parse_hash_v(txid_s, "txid")?;
                    let Some(vout_v) = obj.get("vout").filter(|v| v.is_number()) else {
                        return Err((
                            RPC_INVALID_PARAMETER,
                            "Invalid parameter, missing vout key".into(),
                        ));
                    };
                    let Some(vout) = vout_v.as_i64().and_then(|n| i32::try_from(n).ok()) else {
                        return Err((RPC_MISC_ERROR, "JSON integer out of range".into()));
                    };
                    if vout < 0 {
                        return Err((
                            RPC_INVALID_PARAMETER,
                            "Invalid parameter, vout cannot be negative".into(),
                        ));
                    }
                    let mut sequence = default_seq;
                    if let Some(seq_v) = obj.get("sequence").filter(|v| v.is_number()) {
                        let Some(seq) = seq_v.as_i64() else {
                            return Err((RPC_MISC_ERROR, "JSON integer out of range".into()));
                        };
                        if !(0..=u32::MAX as i64).contains(&seq) {
                            return Err((
                                RPC_INVALID_PARAMETER,
                                "Invalid parameter, sequence number is out of range".into(),
                            ));
                        }
                        sequence = seq as u32;
                    }
                    txins.push(avila_consensus::transaction::TxIn {
                        previous_output: OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        script_sig: Script::new(Vec::new()),
                        sequence,
                        witness: avila_consensus::transaction::Witness::EMPTY,
                    });
                }
                // NormalizeOutputs + ParseOutputs — dict form iterates
                // its key order; array form requires single-pair
                // objects and preserves duplicates for the checks.
                let pairs: Vec<(&str, &Value)> = match &outputs {
                    Value::Null => {
                        return Err((
                            RPC_INVALID_PARAMETER,
                            "Invalid parameter, output argument must be non-null".into(),
                        ));
                    }
                    Value::Object(map) => map.iter().map(|(k, v)| (k.as_str(), v)).collect(),
                    Value::Array(items) => {
                        let mut pairs = Vec::new();
                        for item in items {
                            let Some(obj) = item.as_object() else {
                                return Err((
                                    RPC_INVALID_PARAMETER,
                                    "Invalid parameter, key-value pair not an object as expected"
                                        .into(),
                                ));
                            };
                            if obj.len() != 1 {
                                return Err((
                                    RPC_INVALID_PARAMETER,
                                    "Invalid parameter, key-value pair must contain exactly one key"
                                        .into(),
                                ));
                            }
                            // len == 1 was just enforced — the sole
                            // pair is the output's key and value.
                            if let Some((k, v)) = obj.iter().next() {
                                pairs.push((k.as_str(), v));
                            }
                        }
                        pairs
                    }
                    other => {
                        return Err((RPC_TYPE_ERROR, field_type_message(other, "array")));
                    }
                };
                let mut txouts = Vec::new();
                let mut seen_scripts = std::collections::HashSet::new();
                let mut has_data = false;
                for (key, value) in pairs {
                    if key == "data" {
                        if has_data {
                            return Err((
                                RPC_INVALID_PARAMETER,
                                "Invalid parameter, duplicate key: data".into(),
                            ));
                        }
                        has_data = true;
                        // ParseHexV on getValStr — non-strings stringify
                        // (data:7 → "7"), then IsHex: nonempty, even
                        // length, all hex digits.
                        let s = val_str(value);
                        let ok = !s.is_empty()
                            && s.len().is_multiple_of(2)
                            && s.bytes().all(|c| c.is_ascii_hexdigit());
                        let Some(bytes) = ok.then(|| hex::decode(&s).ok()).flatten() else {
                            return Err((
                                RPC_INVALID_PARAMETER,
                                format!("Data must be hexadecimal string (not '{s}')"),
                            ));
                        };
                        let mut script = vec![avila_consensus::script::OP_RETURN];
                        script.extend_from_slice(&avila_consensus::script::push_slice(&bytes));
                        txouts.push(avila_consensus::transaction::TxOut {
                            value: 0,
                            script_pubkey: Script::new(script),
                        });
                    } else {
                        // ParseOutputs: the amount parses before the
                        // address validates, and dedup is on the
                        // decoded destination (its script here).
                        let amount = amount_from_value(value)?;
                        let Some(script) = avila_consensus::address::address_to_script(key, params)
                        else {
                            return Err((
                                RPC_INVALID_ADDRESS_OR_KEY,
                                format!("Invalid Bitcoin address: {key}"),
                            ));
                        };
                        if !seen_scripts.insert(script.as_bytes().to_vec()) {
                            return Err((
                                RPC_INVALID_PARAMETER,
                                format!("Invalid parameter, duplicated address: {key}"),
                            ));
                        }
                        txouts.push(avila_consensus::transaction::TxOut {
                            value: amount,
                            script_pubkey: script,
                        });
                    }
                }
                // The combination check runs last — after every input
                // and output parsed.
                if rbf == Some(true)
                    && !txins.is_empty()
                    && !txins.iter().any(|i| i.sequence <= 0xffff_fffd)
                {
                    return Err((
                        RPC_INVALID_PARAMETER,
                        "Invalid parameter combination: Sequence number(s) contradict replaceable \
                         option"
                            .into(),
                    ));
                }
                let tx = Transaction {
                    version: 2, // CTransaction::CURRENT_VERSION
                    inputs: txins,
                    outputs: txouts,
                    lock_time: locktime,
                };
                Ok(json!(hex::encode(&tx.encode())))
            })
        }
        // Core's createmultisig (rpc/output_script.cpp) — n-of-m
        // multisig construction: keys parse first (HexToPubKey), then
        // the address type, then AddAndGetMultisigDestination's checks
        // in order (required ≥ 1, enough keys, ≤ 20 keys, ≤ 520-byte
        // redeemScript). Uncompressed keys silently drop segwit types
        // to legacy with a warning.
        "createmultisig" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() < 2 || arr.len() > 3 {
                return help_error(CREATEMULTISIG_HELP);
            }
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if !arr[0].is_number() {
                type_errors.push((1, "nrequired", &arr[0], "number"));
            }
            if !arr[1].is_array() {
                type_errors.push((2, "keys", &arr[1], "array"));
            }
            if let Some(at) = arr.get(2)
                && !(at.is_string() || at.is_null())
            {
                type_errors.push((3, "address_type", at, "string"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            // getInt<int> on nrequired, then HexToPubKey per element —
            // get_str (non-string → bare -3), hex check, then the
            // curve-point check.
            let Some(required) = arr[0].as_i64().and_then(|n| i32::try_from(n).ok()) else {
                return (
                    Value::Null,
                    Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                );
            };
            let mut pubkeys: Vec<Vec<u8>> = Vec::new();
            for key in arr[1].as_array().map(Vec::as_slice).unwrap_or(&[]) {
                let Some(s) = key.as_str() else {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, field_type_message(key, "string"))),
                    );
                };
                // IsHex: nonempty, even length, all hex digits.
                let is_hex = !s.is_empty()
                    && s.len().is_multiple_of(2)
                    && s.bytes().all(|c| c.is_ascii_hexdigit());
                let Some(pk) = is_hex.then(|| hex::decode(s).ok()).flatten() else {
                    return (
                        Value::Null,
                        Some((
                            RPC_INVALID_ADDRESS_OR_KEY,
                            format!("Pubkey \"{s}\" must be a hex string"),
                        )),
                    );
                };
                if !avila_consensus::descriptor::pubkey_is_valid(&pk) {
                    return (
                        Value::Null,
                        Some((
                            RPC_INVALID_ADDRESS_OR_KEY,
                            format!("Pubkey \"{s}\" must be cryptographically valid."),
                        )),
                    );
                }
                pubkeys.push(pk);
            }
            // ParseOutputType — absent/null is legacy; bech32m is a
            // named-but-refused type.
            let output_type = match arr.get(2) {
                None | Some(Value::Null) => "legacy".to_string(),
                Some(Value::String(s)) => match s.as_str() {
                    "legacy" | "p2sh-segwit" | "bech32" => s.clone(),
                    "bech32m" => {
                        return (
                            Value::Null,
                            Some((
                                RPC_INVALID_ADDRESS_OR_KEY,
                                "createmultisig cannot create bech32m multisig addresses".into(),
                            )),
                        );
                    }
                    _ => {
                        return (
                            Value::Null,
                            Some((
                                RPC_INVALID_ADDRESS_OR_KEY,
                                format!("Unknown address type '{s}'"),
                            )),
                        );
                    }
                },
                _ => unreachable!("address_type type-checked above"),
            };
            let keys: Vec<String> = arr[1]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|k| k.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default();
            chain_query(queries, move |cs, _| {
                let params = cs.tree().params();
                // AddAndGetMultisigDestination — bounds before build.
                if required < 1 {
                    return Err((
                        RPC_INVALID_PARAMETER,
                        "a multisignature address must require at least one key to redeem".into(),
                    ));
                }
                if pubkeys.len() < required as usize {
                    return Err((
                        RPC_INVALID_PARAMETER,
                        format!(
                            "not enough keys supplied (got {} keys, but need at least {required} \
                             to redeem)",
                            pubkeys.len()
                        ),
                    ));
                }
                if pubkeys.len() > 20 {
                    return Err((
                        RPC_INVALID_PARAMETER,
                        "Number of keys involved in the multisignature address creation > 20\n\
                         Reduce the number"
                            .into(),
                    ));
                }
                // OP_n <pk>… OP_m OP_CHECKMULTISIG, insertion order —
                // duplicate keys are allowed.
                let mut inner = avila_consensus::script::push_int(i64::from(required));
                for pk in &pubkeys {
                    inner.extend_from_slice(&avila_consensus::script::push_slice(pk));
                }
                inner.extend_from_slice(&avila_consensus::script::push_int(pubkeys.len() as i64));
                inner.push(avila_consensus::script::OP_CHECKMULTISIG);
                if inner.len() > 520 {
                    return Err((
                        RPC_INVALID_PARAMETER,
                        format!("redeemScript exceeds size limit: {} > 520", inner.len()),
                    ));
                }
                // Any uncompressed key disables segwit — the output
                // silently becomes legacy and the warning fires.
                let uncompressed = pubkeys.iter().any(|pk| pk.len() == 65);
                let mut warnings = Vec::new();
                let effective_type = if uncompressed && output_type != "legacy" {
                    warnings.push(
                        "Unable to make chosen address type, please ensure no uncompressed public \
                         keys are present."
                            .to_string(),
                    );
                    "legacy"
                } else {
                    output_type.as_str()
                };
                // Destination script: P2SH(inner) for legacy,
                // P2WSH(inner) for bech32, P2SH-P2WSH for p2sh-segwit.
                let (dest_script, descriptor) = match effective_type {
                    "bech32" => {
                        let wsh = Script::new(
                            [
                                &[avila_consensus::script::OP_0][..],
                                &avila_consensus::script::push_slice(
                                    &avila_consensus::hash::sha256(&inner),
                                )[..],
                            ]
                            .concat(),
                        );
                        (wsh, format!("wsh(multi({},{}))", required, keys.join(",")))
                    }
                    "p2sh-segwit" => {
                        let wsh = Script::new(
                            [
                                &[avila_consensus::script::OP_0][..],
                                &avila_consensus::script::push_slice(
                                    &avila_consensus::hash::sha256(&inner),
                                )[..],
                            ]
                            .concat(),
                        );
                        let sh = Script::new(
                            [
                                &[avila_consensus::script::OP_HASH160, 0x14][..],
                                &avila_consensus::hash::hash160(wsh.as_bytes())[..],
                                &[avila_consensus::script::OP_EQUAL][..],
                            ]
                            .concat(),
                        );
                        (
                            sh,
                            format!("sh(wsh(multi({},{})))", required, keys.join(",")),
                        )
                    }
                    _ => {
                        let sh = Script::new(
                            [
                                &[avila_consensus::script::OP_HASH160, 0x14][..],
                                &avila_consensus::hash::hash160(&inner)[..],
                                &[avila_consensus::script::OP_EQUAL][..],
                            ]
                            .concat(),
                        );
                        (sh, format!("sh(multi({},{}))", required, keys.join(",")))
                    }
                };
                let inner_hex = hex::encode(&inner);
                let Some(address) = script_address(&dest_script, params) else {
                    return Err((RPC_MISC_ERROR, "internal error".into()));
                };
                let mut out = json!({
                    "address": address,
                    "redeemScript": inner_hex,
                    "descriptor": format!(
                        "{descriptor}#{}",
                        avila_consensus::descriptor::descriptor_checksum(&descriptor)
                    ),
                });
                if !warnings.is_empty() {
                    out["warnings"] = json!(warnings);
                }
                Ok(out)
            })
        }
        "prioritisetransaction" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() != 3 {
                return help_error(PRIORITISETRANSACTION_HELP);
            }
            // RPCHelpMan type pass: txid a string, dummy numeric or
            // null, fee_delta numeric — every bad argument collected.
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if !arr[0].is_string() {
                type_errors.push((1, "txid", &arr[0], "string"));
            }
            if !(arr[1].is_number() || arr[1].is_null()) {
                type_errors.push((2, "dummy", &arr[1], "number"));
            }
            if !arr[2].is_number() {
                type_errors.push((3, "fee_delta", &arr[2], "number"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            // Body order (Core's prioritisetransaction): ParseHashV the
            // txid, then getInt<int64> on fee_delta, then the dummy
            // compatibility check.
            let txid: Txid = match parse_hash_v(arr[0].as_str().unwrap_or_default(), "txid") {
                Ok(h) => h,
                Err(e) => return (Value::Null, Some(e)),
            };
            let Some(fee_delta) = arr[2].as_i64() else {
                return (
                    Value::Null,
                    Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                );
            };
            if arr[1].as_f64().is_some_and(|d| d != 0.0) {
                return (
                    Value::Null,
                    Some((
                        RPC_INVALID_PARAMETER,
                        "Priority is no longer supported, dummy argument to \
                         prioritisetransaction must be 0."
                            .into(),
                    )),
                );
            }
            chain_query(queries, move |_cs, mgr| {
                mgr.mempool().prioritise(&txid, fee_delta);
                Ok(json!(true))
            })
        }
        // Core's getprioritisedtransactions — the mapDeltas dump:
        // txid-keyed, sorted by the txid's raw bytes (Core's std::map
        // order), modified_fee present only for pooled transactions.
        "getprioritisedtransactions" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if !arr.is_empty() {
                return help_error(GETPRIORITISEDTRANSACTIONS_HELP);
            }
            chain_query(queries, |_cs, mgr| {
                let pool = mgr.mempool();
                let mut deltas: Vec<(&Txid, &i64)> = pool.deltas().iter().collect();
                deltas.sort_by_key(|(txid, _)| *txid.as_bytes());
                let mut out = serde_json::Map::new();
                for (txid, delta) in deltas {
                    let entry = pool.entry(txid);
                    out.insert(
                        txid.to_string(),
                        match entry {
                            Some(e) => json!({
                                "fee_delta": delta,
                                "in_mempool": true,
                                "modified_fee": e.modified_fee(),
                            }),
                            None => json!({
                                "fee_delta": delta,
                                "in_mempool": false,
                            }),
                        },
                    );
                }
                Ok(Value::Object(out))
            })
        }
        "submitblock" => {
            let Some(raw) = param(params, 0, "hexdata").and_then(Value::as_str) else {
                return missing_params("hexdata");
            };
            let Ok(bytes) = hex::decode(raw) else {
                return (
                    Value::Null,
                    Some((RPC_DESERIALIZATION_ERROR, "Block decode failed".into())),
                );
            };
            chain_query(queries, move |cs, mgr| {
                let block = match avila_consensus::block::Block::decode(&bytes) {
                    Ok(b) => b,
                    Err(_) => {
                        return Err((RPC_DESERIALIZATION_ERROR, "Block decode failed".into()));
                    }
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                // Core's submitblock reports a status STRING in result —
                // errors are only for decode/parameter failures.
                match cs.accept_block(&block, now) {
                    Ok(avila_consensus::chainstate::Acceptance::Connected { height, .. }) => {
                        // Purge confirmed txs, then relay the new tip
                        // (Core's NewPoWValidBlock fan-out — no source
                        // peer for a local submission).
                        mgr.mempool().on_block_connected(&block, height);
                        mgr.announce_tip(cs);
                        Ok(Value::Null)
                    }
                    Ok(avila_consensus::chainstate::Acceptance::AlreadyKnown { .. }) => {
                        Ok(json!("duplicate"))
                    }
                    Ok(avila_consensus::chainstate::Acceptance::Parked { .. }) => {
                        Ok(json!("inconclusive"))
                    }
                    Err(avila_consensus::chainstate::BlockRejection::CachedInvalid) => {
                        Ok(json!("duplicate-invalid"))
                    }
                    Err(rejection) => Ok(json!(rejection.reason().into_owned())),
                }
            })
        }
        "submitheader" => {
            let Some(raw) = param(params, 0, "hexdata").and_then(Value::as_str) else {
                return missing_params("hexdata");
            };
            let Ok(bytes) = hex::decode(raw) else {
                return (
                    Value::Null,
                    Some((
                        RPC_DESERIALIZATION_ERROR,
                        "Block header decode failed".into(),
                    )),
                );
            };
            chain_query(queries, move |cs, _mgr| {
                let Ok(header) = avila_consensus::header::BlockHeader::decode(&bytes) else {
                    return Err((
                        RPC_DESERIALIZATION_ERROR,
                        "Block header decode failed".into(),
                    ));
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                match cs.accept_header(&header, now) {
                    Ok(_) => Ok(Value::Null),
                    Err(avila_consensus::chainstate::BlockRejection::Header(
                        avila_consensus::chain::ChainError::UnknownParent(prev),
                    )) => Err((
                        RPC_VERIFY_ERROR,
                        format!("Must submit previous header ({prev}) first"),
                    )),
                    Err(rejection) => Err((RPC_VERIFY_ERROR, rejection.reason().into_owned())),
                }
            })
        }
        "preciousblock" => {
            let [v] = params.as_array().map(Vec::as_slice).unwrap_or(&[]) else {
                return help_error(PRECIOUSBLOCK_HELP);
            };
            let Some(s) = v.as_str() else {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(1, "blockhash", v, "string"),
                    )),
                );
            };
            let hash: BlockHash = match parse_hash_v(s, "blockhash") {
                Ok(h) => h,
                Err(e) => return (Value::Null, Some(e)),
            };
            chain_query(queries, move |cs, _mgr| match cs.precious_block(&hash) {
                Ok(true) => Ok(Value::Null),
                Ok(false) => Err((RPC_INVALID_ADDRESS_OR_KEY, "Block not found".into())),
                Err(_) => Err((RPC_MISC_ERROR, "preciousblock revalidation failed".into())),
            })
        }
        "getchaintxstats" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() > 2 {
                return help_error(GETCHAINTXSTATS_HELP);
            }
            // RPCHelpMan type pass: nblocks numeric, blockhash a
            // string; every bad argument is collected into one
            // "Wrong type passed" list. Null means default.
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if let Some(v) = arr.first().filter(|v| !(v.is_number() || v.is_null())) {
                type_errors.push((1, "nblocks", v, "number"));
            }
            if let Some(v) = arr.get(1).filter(|v| !(v.is_string() || v.is_null())) {
                type_errors.push((2, "blockhash", v, "string"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            // Core's body resolves the blockhash argument before
            // reading nblocks — a bad hash wins over a bad count.
            let hash = match arr.get(1) {
                None | Some(Value::Null) => None,
                Some(Value::String(s)) => match parse_hash_v(s, "blockhash") {
                    Ok(h) => Some(h),
                    Err(e) => return (Value::Null, Some(e)),
                },
                _ => unreachable!(),
            };
            let raw_nblocks = arr.first().cloned();
            chain_query(queries, move |cs, _mgr| {
                // Core resolves the block before reading nblocks —
                // an unknown hash reports -5 ahead of a -1 int error.
                if hash.is_some_and(|h| !cs.tree().contains(&h)) {
                    return Err((RPC_INVALID_ADDRESS_OR_KEY, "Block not found".into()));
                }
                // getInt<int>: non-integral or out-of-range is -1.
                let nblocks = match raw_nblocks {
                    None | Some(Value::Null) => None,
                    Some(v) => match v.as_i64().and_then(|n| i32::try_from(n).ok()) {
                        Some(n) => Some(i64::from(n)),
                        None => return Err((RPC_MISC_ERROR, "JSON integer out of range".into())),
                    },
                };
                match cs.chain_tx_stats(hash.as_ref(), nblocks) {
                    Ok(s) => {
                        let mut o = serde_json::Map::new();
                        o.insert("time".into(), s.time.into());
                        if let Some(n) = s.tx_count {
                            o.insert("txcount".into(), n.into());
                        }
                        o.insert(
                            "window_final_block_hash".into(),
                            s.final_hash.to_string().into(),
                        );
                        o.insert("window_final_block_height".into(), s.final_height.into());
                        o.insert("window_block_count".into(), s.window_block_count.into());
                        if let Some(n) = s.window_interval {
                            o.insert("window_interval".into(), n.into());
                        }
                        if let Some(n) = s.window_tx_count {
                            o.insert("window_tx_count".into(), n.into());
                        }
                        if let Some(r) = s.tx_rate {
                            o.insert("txrate".into(), float_g16(r));
                        }
                        Ok(Value::Object(o))
                    }
                    Err(avila_consensus::chainstate::TxStatsError::UnknownBlock) => {
                        Err((RPC_INVALID_ADDRESS_OR_KEY, "Block not found".into()))
                    }
                    Err(avila_consensus::chainstate::TxStatsError::BadWindow) => Err((
                        RPC_INVALID_PARAMETER,
                        "Invalid block count: should be between 0 and the block's height - 1"
                            .into(),
                    )),
                }
            })
        }
        "gettxoutsetinfo" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() > 3 {
                return help_error(GETTXOUTSETINFO_HELP);
            }
            // RPCHelpMan type pass: hash_type a string, use_index a
            // boolean; hash_or_height is declared skip_type_check, so
            // any JSON value reaches the body. Null means default.
            let mut type_errors: Vec<(usize, &str, &Value, &str)> = Vec::new();
            if let Some(v) = arr.first().filter(|v| !(v.is_string() || v.is_null())) {
                type_errors.push((1, "hash_type", v, "string"));
            }
            if let Some(v) = arr.get(2).filter(|v| !(v.is_boolean() || v.is_null())) {
                type_errors.push((3, "use_index", v, "bool"));
            }
            if !type_errors.is_empty() {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_list(&type_errors))),
                );
            }
            // The body parses hash_type before touching the others — a
            // bad value beats the coinstatsindex check.
            let hash_type = match arr.first() {
                None | Some(Value::Null) => {
                    avila_consensus::coinstats::CoinStatsHashType::HashSerialized
                }
                Some(Value::String(s)) => match s.as_str() {
                    "hash_serialized_3" => {
                        avila_consensus::coinstats::CoinStatsHashType::HashSerialized
                    }
                    "muhash" => avila_consensus::coinstats::CoinStatsHashType::MuHash,
                    "none" => avila_consensus::coinstats::CoinStatsHashType::None,
                    other => {
                        return (
                            Value::Null,
                            Some((
                                RPC_INVALID_PARAMETER,
                                format!("'{other}' is not a valid hash_type"),
                            )),
                        );
                    }
                },
                _ => unreachable!(),
            };
            // No coinstatsindex: any non-null target is rejected before
            // use_index or the value itself are consulted.
            if arr.get(1).is_some_and(|v| !v.is_null()) {
                return (
                    Value::Null,
                    Some((
                        RPC_INVALID_PARAMETER,
                        "Querying specific block heights requires coinstatsindex".into(),
                    )),
                );
            }
            chain_query(queries, move |cs, _mgr| {
                let s = cs.coin_stats(hash_type);
                let mut o = serde_json::Map::new();
                o.insert("height".into(), s.height.into());
                o.insert("bestblock".into(), s.best_block.to_string().into());
                o.insert("txouts".into(), s.txouts.into());
                o.insert("bogosize".into(), s.bogo_size.into());
                use avila_consensus::coinstats::CoinStatsHashType as H;
                match (hash_type, s.hash_serialized) {
                    (H::HashSerialized, Some(h)) => {
                        o.insert("hash_serialized_3".into(), h.to_string().into());
                    }
                    (H::MuHash, Some(h)) => {
                        o.insert("muhash".into(), h.to_string().into());
                    }
                    _ => {}
                }
                let Some(total) = s.total_amount else {
                    return Err((
                        RPC_INTERNAL_ERROR,
                        "total_amount overflowed MoneyRange".into(),
                    ));
                };
                o.insert("total_amount".into(), (total as f64 / 100_000_000.0).into());
                o.insert("transactions".into(), s.transactions.into());
                o.insert("disk_size".into(), s.disk_size.into());
                Ok(Value::Object(o))
            })
        }
        "generatetoaddress" => {
            let Some(nblocks) = param(params, 0, "nblocks").and_then(Value::as_u64) else {
                return missing_params("nblocks address");
            };
            let Some(address) = param(params, 1, "address")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                return missing_params("address");
            };
            let maxtries = param(params, 2, "maxtries")
                .and_then(Value::as_u64)
                .unwrap_or(1_000_000);
            chain_query(queries, move |cs, mgr| {
                let params = *cs.tree().params();
                let Some(script) = avila_consensus::address::address_to_script(&address, &params)
                else {
                    return Err((
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "Error: Invalid address".to_string(),
                    ));
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                let mut hashes = Vec::with_capacity(nblocks as usize);
                for _ in 0..nblocks {
                    let template = mgr
                        .mempool_ref()
                        .build_template(cs, script.clone(), now)
                        .map_err(|e| (RPC_MISC_ERROR, format!("template: {e}")))?;
                    hashes.push(mine_and_connect(cs, mgr, template.block, maxtries, now)?);
                }
                Ok(json!(hashes))
            })
        }
        "generateblock" => {
            let Some(output) = param(params, 0, "output")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                return missing_params("output transactions");
            };
            let Some(tx_args) = param(params, 1, "transactions").and_then(Value::as_array) else {
                return missing_params("transactions");
            };
            // Owned strings — the closure is 'static.
            let tx_args: Vec<String> = tx_args
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            chain_query(queries, move |cs, mgr| {
                let params = *cs.tree().params();
                let script = avila_consensus::descriptor::output_to_script(&output, &params)
                    .map_err(|_| {
                        (
                            RPC_INVALID_ADDRESS_OR_KEY,
                            "Error: Invalid address or descriptor".to_string(),
                        )
                    })?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as u32)
                    .unwrap_or(0);
                // Core resolves each entry as a mempool txid first (the
                // string parses as a 64-hex hash) and falls back to a
                // raw transaction, which is admitted to the pool before
                // mining — the block's connect then purges it anyway.
                let mut txs: Vec<(Transaction, i64)> = Vec::with_capacity(tx_args.len());
                for s in &tx_args {
                    if let Ok(txid) = s.parse::<Txid>() {
                        let Some(entry) = mgr.mempool_ref().entry(&txid) else {
                            return Err((
                                RPC_INVALID_ADDRESS_OR_KEY,
                                format!("Transaction {s} not in mempool."),
                            ));
                        };
                        txs.push((entry.tx.clone(), entry.fee));
                        continue;
                    }
                    let tx = hex::decode(s)
                        .ok()
                        .and_then(|b| Transaction::decode(&b).ok())
                        .ok_or_else(|| {
                            (
                                RPC_DESERIALIZATION_ERROR,
                                format!(
                                    "Transaction decode failed for {s}. Make sure the tx has at least one input."
                                ),
                            )
                        })?;
                    let txid = mgr
                        .mempool()
                        .accept_tx(tx, cs, now)
                        .map_err(|e| (RPC_VERIFY_ERROR, e.to_string()))?;
                    let entry = mgr
                        .mempool_ref()
                        .entry(&txid)
                        .ok_or((RPC_VERIFY_ERROR, "tx lost after admission".to_string()))?;
                    txs.push((entry.tx.clone(), entry.fee));
                }
                let block = mgr
                    .mempool_ref()
                    .build_explicit_block(cs, script, &txs, now)
                    .map_err(|e| (RPC_MISC_ERROR, format!("template: {e}")))?;
                let hash = mine_and_connect(cs, mgr, block, 1_000_000, now)?;
                Ok(json!({ "hash": hash }))
            })
        }
        "getblocktemplate" => chain_query(queries, |cs, mgr| {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            // No wallet exists — the coinbase pays Core's default
            // `OP_TRUE` anyone-can-spend script (what Core's
            // BlockAssembler uses when no payout script is supplied).
            let template = mgr
                .mempool_ref()
                .build_template(cs, Script::new(vec![avila_consensus::script::OP_1]), now)
                .map_err(|e| (RPC_MISC_ERROR, format!("template: {e}")))?;
            let block = &template.block;
            let height = template.height;
            let tip = cs.tip_hash();
            let mtp = cs.tree().median_time_past(&tip).unwrap_or(0);
            // In-block txid → index in the transactions array (1-based,
            // coinbase excluded) for `depends`.
            let position: std::collections::HashMap<Txid, usize> = block
                .transactions
                .iter()
                .enumerate()
                .skip(1)
                .map(|(i, tx)| (tx.txid(), i))
                .collect();
            let flags =
                avila_consensus::script::block_script_flags(cs.tree().params(), height, &tip);
            let pool = mgr.mempool_ref();
            let txs: Vec<Value> = block
                .transactions
                .iter()
                .skip(1)
                .map(|tx| {
                    let txid = tx.txid();
                    let mut depends: Vec<usize> = tx
                        .inputs
                        .iter()
                        .filter_map(|i| position.get(&i.previous_output.txid))
                        .copied()
                        .collect();
                    depends.sort_unstable();
                    depends.dedup();
                    // GetTransactionSigOpCost: legacy + p2sh + witness.
                    let mut sigops = 0u64;
                    for input in &tx.inputs {
                        if let Some(coin) = pool.resolve(cs, &input.previous_output) {
                            let spk = &coin.out.script_pubkey;
                            sigops += spk.sig_ops(false);
                            sigops += if spk.is_p2sh() {
                                spk.p2sh_sig_ops(&input.script_sig)
                            } else {
                                input.script_sig.sig_ops(false)
                            };
                            sigops += avila_consensus::script::count_witness_sig_ops(
                                &input.script_sig,
                                spk,
                                &input.witness,
                                flags,
                            );
                        }
                    }
                    let fee = pool.entry(&txid).map(|e| e.fee).unwrap_or(0);
                    json!({
                        "data": hex::encode(&tx.encode()),
                        "txid": txid.to_string(),
                        "hash": tx.wtxid().to_string(),
                        "depends": depends,
                        "fee": fee,
                        "sigops": sigops,
                        "weight": tx.weight(),
                    })
                })
                .collect();
            let target = template.block.header.bits.expand().value;
            // `!segwit` is Core's mandatory-rule marker: a miner that
            // can't enforce segwit produces invalid blocks. `taproot`
            // is informational (always-active on regtest, buried on
            // mainnet/signet/testnet4).
            let mut rules = vec!["csv"];
            if flags.contains(avila_consensus::script::ScriptFlags::WITNESS) {
                rules.push("!segwit");
            }
            if flags.contains(avila_consensus::script::ScriptFlags::TAPROOT) {
                rules.push("taproot");
            }
            // `vbavailable` advertises BIP9 deployments in
            // started/locked_in at the tip — keyed by name, valued by
            // the version bit number (Core's getblocktemplate).
            let params = cs.tree().params();
            let tip_node = cs.tree().tip();
            let mut vbavailable = serde_json::Map::new();
            for dep in params.bip9_deployments.iter() {
                let st =
                    avila_consensus::bip9::state(cs.tree(), Some(&tip_node.hash()), dep, params);
                use avila_consensus::bip9::Bip9State;
                if matches!(st, Bip9State::Started | Bip9State::LockedIn) {
                    vbavailable.insert(dep.name.to_string(), json!(dep.bit));
                }
            }
            let mut out = json!({
                // Core's modern capability set — `proposal` is the only
                // extension bitcoind 25+ advertises.
                "capabilities": ["proposal"],
                "version": block.header.version,
                "rules": rules,
                "vbavailable": vbavailable,
                "vbrequired": 0,
                "previousblockhash": tip.to_string(),
                "transactions": txs,
                // Core omits `flags` when the coinbase aux is empty.
                "coinbaseaux": {},
                "coinbasevalue": block.transactions[0].outputs[0].value,
                // Core's longpollid = tip hash + candidate height.
                "longpollid": format!("{}{}", tip, height),
                "target": target.to_hex(),
                "mintime": mtp + 1,
                "mutable": ["time", "transactions", "prevblock"],
                "noncerange": "00000000ffffffff",
                "sigoplimit": 80_000,
                "sizelimit": 4_000_000,
                "weightlimit": 4_000_000,
                "curtime": now,
                "bits": format!("{:08x}", block.header.bits.0),
                "height": height,
            });
            // BIP22: the witness commitment script a miner must carry.
            // build_template adds it to every block once segwit is
            // active — find it by the OP_RETURN + magic prefix rather
            // than assuming an output index.
            let commitment = block.transactions[0].outputs.iter().find(|o| {
                let b = o.script_pubkey.as_bytes();
                b.len() >= 6
                    && b[0] == avila_consensus::script::OP_RETURN
                    && b[1] == 0x24
                    && b[2..6] == avila_mempool::template::WITNESS_COMMITMENT_MAGIC
            });
            if let Some(out0) = commitment {
                out["default_witness_commitment"] =
                    json!(hex::encode(out0.script_pubkey.as_bytes()));
            }
            Ok(out)
        }),
        "getorphantxs" => chain_query(queries, |_, mgr| {
            Ok(json!(
                mgr.mempool_ref()
                    .orphan_txids()
                    .iter()
                    .map(|t| t.to_string())
                    .collect::<Vec<_>>()
            ))
        }),
        "getmininginfo" => chain_query(queries, |cs, mgr| {
            // Core's getmininginfo reports on the connected tip
            // (ActiveTip), not the best header.
            let tip = cs.tip_hash();
            let Some(node) = cs.tree().get(&tip) else {
                return Err((RPC_MISC_ERROR, "tip not indexed".into()));
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            // `next` is what the next block's header would carry —
            // the same `required_bits` the template builder used.
            let next = avila_consensus::pow::required_bits(
                node.height,
                &node.header,
                now,
                cs.tree().params(),
                cs.tree(),
            )
            .ok();
            // `currentblock*` describes the candidate Core refreshes in
            // the background — we build it on demand and report its
            // weight/tx count honestly. Core dropped `currentblocksize`
            // (Knots still emits it); match Core.
            let current = mgr
                .mempool_ref()
                .build_template(cs, Script::new(vec![avila_consensus::script::OP_1]), now)
                .ok();
            // networkhashps — Core's GetNetworkHashPS(120, -1): the
            // default 120-block window at the tip.
            let networkhashps = network_hashps(cs, 120, -1);
            let mut out = json!({
                "blocks": node.height,
                "currentblockweight": current.as_ref().map(|t| t.weight).unwrap_or(0),
                "currentblocktx": current.as_ref().map(|t| t.tx_count).unwrap_or(0),
                "difficulty": core_num(difficulty(node.header.bits.0)),
                "bits": format!("{:08x}", node.header.bits.0),
                "target": node.header.bits.expand().value.to_hex(),
                "networkhashps": core_num(networkhashps),
                "pooledtx": mgr.mempool_ref().len(),
                "chain": format!("{:?}", cs.tree().params().network).to_lowercase(),
                "warnings": [],
            });
            if let Some(bits) = next {
                out["next"] = json!({
                    "height": node.height + 1,
                    "bits": format!("{:08x}", bits.0),
                    "target": bits.expand().value.to_hex(),
                    "difficulty": difficulty(bits.0),
                });
            }
            Ok(out)
        }),
        "getnetworkhashps" => {
            // RPCHelpMan: 0–2 args.
            if params.as_array().is_some_and(|a| a.len() > 2) {
                return help_error(GETNETWORKHASHPS_HELP);
            }
            // `nblocks`: getInt<int> — a float/out-of-i32 value is -1,
            // non-number is -3, 0 and below -1 are -8.
            let nblocks = match param(params, 0, "nblocks") {
                None => 120i64,
                Some(v) if !v.is_number() => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(1, "nblocks", v, "number"),
                        )),
                    );
                }
                Some(v) => match v.as_i64() {
                    Some(n)
                        if !v.is_f64() && n >= i64::from(i32::MIN) && n <= i64::from(i32::MAX) =>
                    {
                        if n == 0 || n < -1 {
                            return (
                                Value::Null,
                                Some((
                                    RPC_INVALID_PARAMETER,
                                    "Invalid nblocks. Must be a positive number or -1.".into(),
                                )),
                            );
                        }
                        n
                    }
                    _ => {
                        return (
                            Value::Null,
                            Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                        );
                    }
                },
            };
            let height = match param(params, 1, "height") {
                None => -1i64,
                Some(v) if v.is_null() => -1,
                Some(v) if !v.is_number() => {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(2, "height", v, "number"))),
                    );
                }
                Some(v) => match v.as_i64() {
                    Some(n)
                        if !v.is_f64() && n >= i64::from(i32::MIN) && n <= i64::from(i32::MAX) =>
                    {
                        n
                    }
                    _ => {
                        return (
                            Value::Null,
                            Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                        );
                    }
                },
            };
            chain_query(queries, move |cs, _| {
                let tip_h = cs.chain().len() as i64 - 1;
                if height < -1 || height > tip_h {
                    return Err((
                        RPC_INVALID_PARAMETER,
                        "Block does not exist at specified height".into(),
                    ));
                }
                Ok(core_num(network_hashps(cs, nblocks, height)))
            })
        }
        "getnettotals" => {
            if params.as_array().is_some_and(|a| !a.is_empty()) {
                return help_error(GETNETTOTALS_HELP);
            }
            chain_query(queries, |_, mgr| {
                let (sent, recv) = mgr.net_totals();
                let timemillis = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                // `uploadtarget` mirrors `-maxuploadtarget=0`
                // (unlimited): no cycle budget is tracked.
                Ok(json!({
                    "totalbytesrecv": recv,
                    "totalbytessent": sent,
                    "timemillis": timemillis,
                    "uploadtarget": {
                        "timeframe": 86400,
                        "target": 0,
                        "target_reached": false,
                        "serve_historical_blocks": true,
                        "bytes_left_in_cycle": 0,
                        "time_left_in_cycle": 0,
                    },
                }))
            })
        }
        "ping" => {
            if params.as_array().is_some_and(|a| !a.is_empty()) {
                return help_error(PING_HELP);
            }
            chain_query(queries, |_, mgr| {
                mgr.ping_all();
                Ok(Value::Null)
            })
        }
        "disconnectnode" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.is_empty() || arr.len() > 2 {
                return help_error(DISCONNECTNODE_HELP);
            }
            let address = &arr[0];
            let nodeid = arr.get(1).unwrap_or(&Value::Null);
            // Type checks precede the either/or check, like Core.
            if !address.is_null() && !address.is_string() {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(1, "address", address, "string"),
                    )),
                );
            }
            if !nodeid.is_null() && !nodeid.is_i64() && !nodeid.is_u64() {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(2, "nodeid", nodeid, "number"),
                    )),
                );
            }
            let by_addr = !address.is_null() && nodeid.is_null();
            let by_id = !nodeid.is_null()
                && (address.is_null() || address.as_str().is_some_and(str::is_empty));
            if !by_addr && !by_id {
                return (
                    Value::Null,
                    Some((
                        RPC_INVALID_PARAMS,
                        "Only one of address and nodeid should be provided.".into(),
                    )),
                );
            }
            // Extract owned values — the query closure must be 'static.
            let address_s = address.as_str().map(str::to_string);
            let nodeid_v = nodeid.as_i64();
            chain_query(queries, move |_, mgr| {
                let success = if let Some(addr) = &address_s {
                    if addr.contains('/') {
                        match parse_subnet(addr) {
                            Some((net, plen)) => mgr.disconnect_by_subnet(&net, plen),
                            None => {
                                return Err((RPC_INVALID_PARAMETER, "Invalid subnet".to_string()));
                            }
                        }
                    } else {
                        mgr.disconnect_by_addr(addr)
                    }
                } else {
                    mgr.disconnect_by_id(nodeid_v.unwrap_or(-1) as u64)
                };
                if success {
                    Ok(Value::Null)
                } else {
                    Err((
                        RPC_CLIENT_NODE_NOT_CONNECTED,
                        "Node not found in connected nodes".to_string(),
                    ))
                }
            })
        }
        "addnode" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() != 2 && arr.len() != 3 && arr.len() != 4 {
                return help_error(ADDNODE_HELP);
            }
            let node = match &arr[0] {
                Value::String(s) => s.clone(),
                v => {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(1, "node", v, "string"))),
                    );
                }
            };
            let command = match &arr[1] {
                Value::String(s) => s.clone(),
                v => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(2, "command", v, "string"),
                        )),
                    );
                }
            };
            if command != "onetry" && command != "add" && command != "remove" {
                return help_error(ADDNODE_HELP);
            }
            // v2transport|connection_type_compat: a *string* in slot 3
            // is the pre-v26 connection_type position; otherwise it's
            // the v2transport bool (we never run BIP324 → NODE_P2P_V2
            // is unset → requesting it errors like Core).
            let mut connection_type = "manual".to_string();
            let read_conn_type = |v: &Value, pos: usize| -> Result<&'static str, (i64, String)> {
                let Some(s) = v.as_str() else {
                    return Err((
                        RPC_TYPE_ERROR,
                        wrong_type_message(pos, "connection_type", v, "string"),
                    ));
                };
                connection_type_from(s).ok_or_else(|| {
                    (
                        RPC_INVALID_PARAMETER,
                        format!("Unknown connection type {s}"),
                    )
                })
            };
            match arr.get(2) {
                Some(Value::String(s)) => {
                    if command == "remove" || arr.len() > 3 {
                        return help_error(ADDNODE_HELP);
                    }
                    match read_conn_type(&Value::String(s.clone()), 3) {
                        Ok(c) => connection_type = c.to_string(),
                        Err(e) => return (Value::Null, Some(e)),
                    }
                }
                Some(Value::Bool(true)) => {
                    return (
                        Value::Null,
                        Some((
                            RPC_INVALID_PARAMETER,
                            "Error: v2transport requested but not enabled (see -v2transport)"
                                .into(),
                        )),
                    );
                }
                Some(Value::Bool(false)) | Some(Value::Null) | None => {}
                Some(v) => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(3, "v2transport|connection_type_compat", v, "bool"),
                        )),
                    );
                }
            }
            if let Some(ct) = arr.get(3)
                && !ct.is_null()
            {
                if command == "remove" {
                    return help_error(ADDNODE_HELP);
                }
                match read_conn_type(ct, 4) {
                    Ok(c) => connection_type = c.to_string(),
                    Err(e) => return (Value::Null, Some(e)),
                }
            }
            chain_query(queries, move |cs, mgr| {
                if command == "onetry" {
                    // OpenNetworkConnection resolves and dials async —
                    // we queue the same bounded attempt.
                    if let Ok(addrs) = node.as_str().to_socket_addrs()
                        && let Some(sock) = addrs.into_iter().next()
                    {
                        let _ = mgr.connect(
                            sock,
                            cs.tree().params().message_start,
                            sock.port() as u64,
                            cs.chain().len() as i32 - 1,
                        );
                    }
                    return Ok(Value::Null);
                }
                if command == "add" {
                    if connection_type != "manual" {
                        return Err((
                            RPC_INVALID_PARAMETER,
                            "connection_type != manual is only supported for \
                             the \"onetry\" command for now"
                                .into(),
                        ));
                    }
                    if !mgr.add_node(node, false) {
                        return Err((
                            RPC_CLIENT_NODE_ALREADY_ADDED,
                            "Error: Node already added".into(),
                        ));
                    }
                } else if command == "remove" && !mgr.remove_node(&node) {
                    return Err((
                        RPC_CLIENT_NODE_NOT_ADDED,
                        "Error: Node could not be removed. It has not \
                         been added previously."
                            .into(),
                    ));
                }
                Ok(Value::Null)
            })
        }
        "setnetworkactive" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() != 1 {
                return help_error(SETNETWORKACTIVE_HELP);
            }
            let state = match &arr[0] {
                Value::Bool(b) => *b,
                v => {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(1, "state", v, "bool"))),
                    );
                }
            };
            chain_query(queries, move |_, mgr| {
                mgr.set_network_active(state);
                Ok(json!(state))
            })
        }
        "setban" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if !(2..=4).contains(&arr.len()) {
                return help_error(SETBAN_HELP);
            }
            // RPCHelpMan's type pass runs before the command parse:
            // subnet str, command str, bantime num, absolute bool.
            if let Some(v) = arr.first().filter(|v| !v.is_string()) {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_message(1, "subnet", v, "string"))),
                );
            }
            if let Some(v) = arr.get(1).filter(|v| !v.is_string()) {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(2, "command", v, "string"),
                    )),
                );
            }
            if let Some(v) = arr.get(2).filter(|v| !v.is_number()) {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(3, "bantime", v, "number"),
                    )),
                );
            }
            if let Some(v) = arr.get(3).filter(|v| !v.is_boolean()) {
                return (
                    Value::Null,
                    Some((RPC_TYPE_ERROR, wrong_type_message(4, "absolute", v, "bool"))),
                );
            }
            let command = arr[1].as_str().unwrap_or_default().to_owned();
            // Command is validated before the subnet (a bad command is
            // the help throw even with a bad subnet).
            if command != "add" && command != "remove" {
                return help_error(SETBAN_HELP);
            }
            let Some(net) = avila_p2p::banman::SubNet::parse(arr[0].as_str().unwrap_or_default())
            else {
                return (
                    Value::Null,
                    Some((
                        RPC_CLIENT_INVALID_IP_OR_SUBNET,
                        "Error: Invalid IP/Subnet".into(),
                    )),
                );
            };
            // getInt<int64>: a non-integral or out-of-range number is
            // UniValue's -1 "JSON integer out of range".
            let bantime = match arr.get(2) {
                None | Some(Value::Null) => 0,
                Some(v) => match v.as_i64() {
                    Some(n) => n,
                    None => {
                        return (
                            Value::Null,
                            Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                        );
                    }
                },
            };
            let absolute = arr.get(3).and_then(Value::as_bool).unwrap_or(false);
            chain_query(queries, move |_, mgr| {
                let now = epoch_secs();
                match command.as_str() {
                    "add" => {
                        // Core checks IsBanned before the bantime math —
                        // an active entry rejects the re-add (a listed-
                        // but-expired one can be re-banned).
                        if mgr.is_subnet_banned(&net, now) {
                            return Err((
                                RPC_CLIENT_NODE_ALREADY_ADDED,
                                "Error: IP/Subnet already banned".into(),
                            ));
                        }
                        let until = if absolute {
                            if bantime <= now {
                                return Err((
                                    RPC_INVALID_PARAMETER,
                                    "Error: Absolute timestamp is in the past".into(),
                                ));
                            }
                            bantime
                        } else {
                            now + if bantime <= 0 {
                                avila_p2p::banman::DEFAULT_BANTIME
                            } else {
                                bantime
                            }
                        };
                        mgr.ban(net, now, until);
                        Ok(Value::Null)
                    }
                    _ => {
                        if !mgr.unban(&net) {
                            return Err((
                                RPC_CLIENT_INVALID_IP_OR_SUBNET,
                                "Error: Unban failed. Requested address/subnet was not previously \
                                 manually banned."
                                    .into(),
                            ));
                        }
                        Ok(Value::Null)
                    }
                }
            })
        }
        "listbanned" => {
            if params.as_array().is_some_and(|a| !a.is_empty()) {
                return help_error(LISTBANNED_HELP);
            }
            chain_query(queries, |_, mgr| {
                let now = epoch_secs();
                let rows: Vec<Value> = mgr
                    .banned_list(now)
                    .iter()
                    .map(|(net, e)| {
                        json!({
                            "address": net.to_string(),
                            "ban_created": e.created,
                            "banned_until": e.until,
                            "ban_duration": e.until - e.created,
                            "time_remaining": e.until - now,
                        })
                    })
                    .collect();
                Ok(Value::Array(rows))
            })
        }
        "clearbanned" => {
            if params.as_array().is_some_and(|a| !a.is_empty()) {
                return help_error(CLEARBANNED_HELP);
            }
            chain_query(queries, |_, mgr| {
                mgr.clear_bans();
                Ok(Value::Null)
            })
        }
        "getrpcinfo" => {
            if params.as_array().is_some_and(|a| !a.is_empty()) {
                return help_error(GETRPCINFO_HELP);
            }
            // Owned copies — the query closure must be 'static.
            let method_name = method.to_string();
            chain_query(queries, move |cs, _mgr| {
                // Core reports the configured debug log path — the
                // chainstate store dir is our per-network datadir.
                // `absolute` (not `canonicalize`): the file need not
                // exist, matching Core which reports the configured
                // path regardless.
                let logpath = cs
                    .store()
                    .and_then(|s| std::path::absolute(s.dir().join("debug.log")).ok())
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_default();
                Ok(json!({
                    "active_commands": [{
                        "method": method_name,
                        "duration": call_start.elapsed().as_micros() as u64,
                    }],
                    "logpath": logpath,
                }))
            })
        }
        "getmemoryinfo" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() > 1 {
                return help_error(GETMEMORYINFO_HELP);
            }
            let mode = match arr.first() {
                None | Some(Value::Null) => "stats",
                Some(Value::String(s)) => s.as_str(),
                Some(v) => {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(1, "mode", v, "string"))),
                    );
                }
            };
            match mode {
                "stats" => (
                    // No locked-page pool: Core's LockedPool block is
                    // reported as the honest all-zero state.
                    json!({"locked": {
                        "used": 0, "free": 0, "total": 0, "locked": 0,
                        "chunks_used": 0, "chunks_free": 0,
                    }}),
                    None,
                ),
                "mallocinfo" => match malloc_info_xml() {
                    Some(xml) => (json!(xml), None),
                    None => (
                        Value::Null,
                        Some((
                            RPC_INVALID_PARAMETER,
                            "mallocinfo mode not supported".into(),
                        )),
                    ),
                },
                other => (
                    Value::Null,
                    Some((RPC_INVALID_PARAMETER, format!("unknown mode {other}"))),
                ),
            }
        }
        "logging" => {
            let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
            if arr.len() > 2 {
                return help_error(LOGGING_HELP);
            }
            // Core type-checks include/exclude as arrays first.
            for (i, name) in ["include", "exclude"].iter().enumerate() {
                if let Some(v) = arr.get(i)
                    && !v.is_null()
                    && !v.is_array()
                {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(i + 1, name, v, "array"))),
                    );
                }
            }
            // Include is applied first, then exclude — an item in both
            // ends excluded (Core evaluates the lists in order).
            let mut state = LOG_CATEGORIES.lock().unwrap_or_else(|p| p.into_inner());
            for (arg_idx, value) in [(0, true), (1, false)] {
                if let Some(list) = arr.get(arg_idx).and_then(|v| v.as_array()) {
                    for item in list {
                        let Some(cat) = item.as_str() else {
                            return (
                                Value::Null,
                                Some((
                                    RPC_TYPE_ERROR,
                                    format!(
                                        "JSON value of type {} is not of expected \
                                         type string",
                                        json_type_name(item),
                                    ),
                                )),
                            );
                        };
                        if cat == "all" || cat == "1" {
                            state.fill(value);
                            continue;
                        }
                        let Some(pos) = LOG_CATEGORY_NAMES.iter().position(|c| *c == cat) else {
                            return (
                                Value::Null,
                                Some((
                                    RPC_INVALID_PARAMETER,
                                    format!("unknown logging category {cat}"),
                                )),
                            );
                        };
                        state[pos] = value;
                    }
                }
            }
            let mut map = serde_json::Map::with_capacity(LOG_CATEGORY_NAMES.len());
            for (i, c) in LOG_CATEGORY_NAMES.iter().enumerate() {
                map.insert((*c).to_string(), json!(state[i]));
            }
            (Value::Object(map), None)
        }
        "getnodeaddresses" => {
            // RPCHelpMan: 0–2 args.
            if params.as_array().is_some_and(|a| a.len() > 2) {
                return help_error(GETNODEADDRESSES_HELP);
            }
            // `count`: getInt<int> — float/out-of-i32 is -1, non-number
            // is -3, negative is -8; 0 returns the whole (filtered) book.
            let count = match param(params, 0, "count") {
                None => 1i64,
                Some(v) if v.is_null() => 1,
                Some(v) if !v.is_number() => {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(1, "count", v, "number"))),
                    );
                }
                Some(v) => match v.as_i64() {
                    Some(n)
                        if !v.is_f64() && n >= i64::from(i32::MIN) && n <= i64::from(i32::MAX) =>
                    {
                        if n < 0 {
                            return (
                                Value::Null,
                                Some((RPC_INVALID_PARAMETER, "Address count out of range".into())),
                            );
                        }
                        n
                    }
                    _ => {
                        return (
                            Value::Null,
                            Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                        );
                    }
                },
            };
            // `network`: ParseNetwork — unknown names are -8.
            let network = match param(params, 1, "network") {
                None => None,
                Some(v) if v.is_null() => None,
                Some(v) if !v.is_string() => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(2, "network", v, "string"),
                        )),
                    );
                }
                Some(v) => {
                    let name = v.as_str().unwrap_or_default();
                    match avila_p2p::addrman::parse_network(name) {
                        Some(n) => Some(n),
                        None => {
                            return (
                                Value::Null,
                                Some((
                                    RPC_INVALID_PARAMETER,
                                    format!("Network not recognized: {name}"),
                                )),
                            );
                        }
                    }
                }
            };
            chain_query(queries, move |_, mgr| {
                let entries = mgr.addr_book().entries(count as usize, network);
                Ok(Value::Array(
                    entries
                        .iter()
                        .map(|e| {
                            json!({
                                "time": e.last_seen,
                                "services": e.addr.services,
                                "address": avila_p2p::addrman::socket_addr(&e.addr)
                                    .ip()
                                    .to_string(),
                                "port": e.addr.port,
                                "network": avila_p2p::addrman::network_name(
                                    avila_p2p::addrman::network_of(&e.addr),
                                ),
                            })
                        })
                        .collect(),
                ))
            })
        }
        "getaddrmaninfo" => {
            if params.as_array().is_some_and(|a| !a.is_empty()) {
                return help_error(GETADDRMANINFO_HELP);
            }
            chain_query(queries, |_, mgr| {
                let counts = mgr.addr_book().network_counts();
                let mut new_total = 0usize;
                let mut tried_total = 0usize;
                let mut out = serde_json::Map::new();
                for net in [
                    avila_p2p::addrman::Network::Ipv4,
                    avila_p2p::addrman::Network::Ipv6,
                    avila_p2p::addrman::Network::Onion,
                    avila_p2p::addrman::Network::I2p,
                    avila_p2p::addrman::Network::Cjdns,
                ] {
                    let (new, tried) = counts
                        .iter()
                        .find(|(n, _, _)| *n == net)
                        .map(|(_, n, t)| (*n, *t))
                        .unwrap_or((0, 0));
                    new_total += new;
                    tried_total += tried;
                    out.insert(
                        avila_p2p::addrman::network_name(net).into(),
                        json!({"new": new, "tried": tried, "total": new + tried}),
                    );
                }
                out.insert(
                    "all_networks".into(),
                    json!({
                        "new": new_total,
                        "tried": tried_total,
                        "total": new_total + tried_total,
                    }),
                );
                Ok(Value::Object(out))
            })
        }
        // Test-only address injection — `addpeeraddress`. Onion/I2P
        // names can't be represented in our 16-byte `NetAddr`, so they
        // take the unparseable path (Core stores them; we report
        // `success:false` without an error string).
        "addpeeraddress" => {
            let arity_ok = params
                .as_array()
                .is_some_and(|a| (2..=3).contains(&a.len()));
            if !arity_ok {
                return help_error(ADDPEERADDRESS_HELP);
            }
            let (Some(address), Some(port_v)) =
                (param(params, 0, "address"), param(params, 1, "port"))
            else {
                return help_error(ADDPEERADDRESS_HELP);
            };
            let Some(addr_str) = address.as_str() else {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(1, "address", address, "string"),
                    )),
                );
            };
            let addr_str = addr_str.to_owned();
            if !port_v.is_number() {
                return (
                    Value::Null,
                    Some((
                        RPC_TYPE_ERROR,
                        wrong_type_message(2, "port", port_v, "number"),
                    )),
                );
            }
            let port = match port_v.as_i64() {
                Some(n) if !port_v.is_f64() && (0..=65535).contains(&n) => n as u16,
                _ => {
                    return (
                        Value::Null,
                        Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                    );
                }
            };
            let tried = match param(params, 2, "tried") {
                None => false,
                Some(v) if v.is_null() => false,
                Some(v) if !v.is_boolean() => {
                    return (
                        Value::Null,
                        Some((RPC_TYPE_ERROR, wrong_type_message(3, "tried", v, "boolean"))),
                    );
                }
                Some(v) => v.as_bool().unwrap_or(false),
            };
            chain_query(queries, move |_, mgr| {
                let mut obj = serde_json::Map::new();
                match addr_str.parse::<std::net::IpAddr>() {
                    Ok(ip) => {
                        use avila_p2p::addrman;
                        use avila_p2p::message::{NODE_NETWORK, NODE_WITNESS};
                        let addr = addrman::net_addr_of(
                            std::net::SocketAddr::new(ip, port),
                            NODE_NETWORK | NODE_WITNESS,
                        );
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as u32)
                            .unwrap_or(0);
                        if mgr.addrbook().add(addr, now, now) {
                            if tried {
                                mgr.addrbook().mark_tried(&addr);
                            }
                            obj.insert("success".into(), json!(true));
                        } else {
                            // Duplicate or unroutable — Core's
                            // AddSingle rejects both identically.
                            obj.insert("error".into(), json!("failed-adding-to-new"));
                            obj.insert("success".into(), json!(false));
                        }
                    }
                    Err(_) => {
                        obj.insert("success".into(), json!(false));
                    }
                }
                Ok(Value::Object(obj))
            })
        }
        "getnetworkinfo" => chain_query(queries, |_cs, mgr| {
            let snaps = mgr.peer_snapshots();
            let inbound = snaps.iter().filter(|p| p.inbound).count();
            // What we offer the network — NODE_NETWORK | NODE_WITNESS.
            let services = avila_p2p::message::NODE_NETWORK | avila_p2p::message::NODE_WITNESS;
            // Reachability is honest: clearnet only unless a proxy was
            // configured (the proxy knob is CLI-side; report onion as
            // unreachable until the config reaches this layer).
            let net = |name: &str, reachable: bool| {
                json!({
                    "name": name,
                    "limited": !reachable,
                    "reachable": reachable,
                    "proxy": "",
                    "proxy_randomize_credentials": false,
                })
            };
            Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "subversion": "/Avila:0.1.0/",
                "protocolversion": avila_p2p::message::PROTOCOL_VERSION,
                "localservices": format!("{services:016x}"),
                "localservicesnames": service_names(services),
                "localrelay": true,
                "timeoffset": 0,
                "networkactive": mgr.network_active(),
                "networks": [
                    net("ipv4", true),
                    net("ipv6", true),
                    net("onion", false),
                    net("i2p", false),
                    net("cjdns", false),
                ],
                "connections": mgr.len(),
                "connections_in": inbound,
                "connections_out": mgr.len() - inbound,
                // No discovered/advertised local addrs yet — Core's
                // regtest answer is the empty list too.
                "localaddresses": [],
                "relayfee": mgr.mempool_ref().min_relay_fee() as f64 / 100_000_000.0,
                "incrementalfee": avila_mempool::INCREMENTAL_RELAY_FEE as f64 / 100_000_000.0,
                "warnings": [],
            }))
        }),
        "getconnectioncount" => (json!(snap.peers), None),
        "uptime" => (json!(snap.elapsed_secs), None),
        "stop" => match stop {
            Some(flag) => {
                flag.store(true, Ordering::Relaxed);
                (json!("Avila node stopping"), None)
            }
            None => (
                Value::Null,
                Some((RPC_MISC_ERROR, "no run loop to stop".into())),
            ),
        },
        "estimatesmartfee" => {
            // RPCHelpMan: 1–2 args.
            if params
                .as_array()
                .is_some_and(|a| a.len() > 2 || a.is_empty())
            {
                return help_error(ESTIMATESMARTFEE_HELP);
            }
            let target_val = param(params, 0, "conf_target");
            let target = match target_val {
                None => return help_error(ESTIMATESMARTFEE_HELP),
                Some(v) if !v.is_number() => {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(1, "conf_target", v, "number"),
                        )),
                    );
                }
                // Core reads it via `getInt<unsigned int>` — a float
                // or out-of-u32 value is UniValue's -1 error before
                // the range check.
                Some(v) if v.is_f64() || v.as_u64().is_none() => {
                    return (
                        Value::Null,
                        Some((RPC_MISC_ERROR, "JSON integer out of range".into())),
                    );
                }
                Some(v) => match v.as_u64() {
                    Some(n) if (1..=1008).contains(&n) => n as u32,
                    _ => {
                        return (
                            Value::Null,
                            Some((
                                RPC_INVALID_PARAMETER,
                                "Invalid conf_target, must be between 1 and 1008".into(),
                            )),
                        );
                    }
                },
            };
            if let Some(v) = param(params, 1, "estimate_mode") {
                if !v.is_null() && !v.is_string() {
                    return (
                        Value::Null,
                        Some((
                            RPC_TYPE_ERROR,
                            wrong_type_message(2, "estimate_mode", v, "string"),
                        )),
                    );
                }
                // `FeeModeFromString` uppercases before matching.
                if let Some(mode) = v.as_str()
                    && !matches!(
                        mode.to_ascii_lowercase().as_str(),
                        "unset" | "economical" | "conservative"
                    )
                {
                    return (
                        Value::Null,
                        Some((
                            RPC_INVALID_PARAMETER,
                            "Invalid estimate_mode parameter, must be one of: \
                             \"unset\", \"economical\", \"conservative\""
                                .into(),
                        )),
                    );
                }
            }
            chain_query(queries, move |_, mgr| {
                match mgr.mempool_ref().estimate_fee(target) {
                    // Core reports feerate in BTC/kvB; our estimator
                    // stores sat/kvB.
                    Some(rate) => Ok(json!({
                        "feerate": rate as f64 / 100_000_000.0,
                        "blocks": target,
                    })),
                    // Core's estimator returns a result object with an
                    // `errors` list when it has no data — not an RPC
                    // error.
                    None => Ok(json!({
                        "errors": ["Insufficient data or no feerate found"],
                        "blocks": 0,
                    })),
                }
            })
        }
        "help" => (
            json!(
                "avila-node JSON-RPC:\n\
                 \x20 chain: getblockcount, getbestblockhash, getblockchaininfo, getchaintips,\n\
                 \x20   getdifficulty,\n\
                 \x20   getblockhash <height>, getblockheader <hash> [verbose],\n\
                 \x20   getblock <hash> [verbosity 0-2], getblockstats <hash|height> [stats],\n\
                 \x20   getdeploymentinfo [blockhash],\n\
                 \x20   getrawtransaction <txid> [verbosity] [blockhash],\n\
                 \x20   decoderawtransaction <hex> [iswitness], getindexinfo [index_name],\n\
                 \x20   gettxout <txid> <n> [include_mempool], decodescript <hex>,\n\
                 \x20   gettxoutproof <txids> [blockhash] [options],\n\
                 \x20   verifytxoutproof <proof> [options], validateaddress <address>,\n\
                 \x20   verifymessage <address> <sig> <msg>,\n\
                 \x20   signmessagewithprivkey <wif> <msg>,\n\
                 \x20   verifychain [checklevel] [nblocks],\n\
                 \x20   getchaintxstats [nblocks] [blockhash],\n\
                 \x20   gettxoutsetinfo [hash_type] [hash_or_height] [use_index]\n\
                 \x20 mempool: getmempoolinfo, getrawmempool [verbose], getmempoolentry <txid>,\n\
                 \x20   getmempoolancestors|getmempooldescendants <txid> [verbose],\n\
                 \x20   gettxspendingprevout <outputs>,\n\
                 \x20   getorphantxs, testmempoolaccept <rawtx | [rawtx,...]>,\n\
                 \x20   createrawtransaction <inputs> <outputs> [locktime] [replaceable],\n\
                 \x20   createmultisig <nrequired> [keys] [address_type],\n\
                 \x20   sendrawtransaction <hex> [maxfeerate] [maxburnamount], savemempool\n\
                 \x20 mining: getblocktemplate, getmininginfo, getnetworkhashps,\n\
                 \x20   submitblock <hex>,\n\
                 \x20   submitheader <hex>, generatetoaddress <n> <address> [maxtries],\n\
                 \x20   generateblock <output> [rawtx/txid,...],\n\
                 \x20   preciousblock <hash>, prioritisetransaction <txid> 0 <delta>,\n\
                 \x20   getprioritisedtransactions,\n\
                 \x20   getblockfrompeer <hash> <peer_id>,\n\
                 \x20   waitforblock <hash> [timeout], waitforblockheight <h> [timeout],\n\
                 \x20   waitfornewblock [timeout]\n\
                 \x20 net:   getpeerinfo, getconnectioncount, getnetworkinfo,\n\
                 \x20   getnettotals, getnodeaddresses [count] [network],\n\
                 \x20   getaddrmaninfo,\n\
                 \x20   addpeeraddress <address> <port> [tried], ping,\n\
                 \x20   disconnectnode [address] [nodeid], addnode <node> <cmd>,\n\
                 \x20   setnetworkactive <state>,\n\
                 \x20   setban <subnet> <add|remove> [bantime] [absolute],\n\
                 \x20   listbanned, clearbanned\n\
                 \x20 misc:  estimatesmartfee <target>, getrpcinfo,\n\
                 \x20   getmemoryinfo [mode], logging [include] [exclude],\n\
                 \x20   uptime, help, stop"
            ),
            None,
        ),
        _ => (
            Value::Null,
            Some((RPC_METHOD_NOT_FOUND, format!("method not found: {method}"))),
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use avila_consensus::params::Network;

    fn snap() -> SyncProgress {
        SyncProgress {
            peers: 2,
            connected_height: 120,
            header_height: 140,
            in_flight: 3,
            established_total: 4,
            disconnects: 1,
            recent: vec![(120, avila_consensus::hash::BlockHash::from_bytes([7u8; 32]))],
            peer_details: Vec::new(),
            mempool: (5, 1, Some(2_000)),
            elapsed_secs: 42,
        }
    }

    /// Snapshot methods take `None` for both optional channels.
    fn snap_dispatch(
        method: &str,
        params: &Value,
        snap: &SyncProgress,
    ) -> (Value, Option<(i64, String)>) {
        dispatch(method, params, snap, None, None, None)
    }

    #[test]
    fn read_only_methods_answer_from_the_snapshot() {
        let snap = snap();
        let (r, e) = snap_dispatch("getblockcount", &Value::Null, &snap);
        assert_eq!(r, json!(120));
        assert!(e.is_none());
        let (_, e) = snap_dispatch("sendtoaddress", &Value::Null, &snap);
        assert_eq!(e.unwrap().0, RPC_METHOD_NOT_FOUND);
        let (r, _) = snap_dispatch("uptime", &Value::Null, &snap);
        assert_eq!(r, json!(42));
        let (r, _) = snap_dispatch("getconnectioncount", &Value::Null, &snap);
        assert_eq!(r, json!(2));
    }

    #[test]
    fn chain_methods_need_the_query_channel() {
        let snap = snap();
        let (_, e) = dispatch("getblockhash", &json!([0]), &snap, None, None, None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    #[test]
    fn cookie_auth_and_base64_roundtrip() {
        // RFC 4648 vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");

        // Cookie write/read roundtrip under a temp dir.
        let dir = std::env::temp_dir().join(format!("avila-rpc-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let token = write_cookie(&dir).unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(read_cookie(&dir).unwrap(), token);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(COOKIE_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "cookie must be owner-only");
        }
        std::fs::remove_dir_all(&dir).unwrap();

        // The expected header value encodes __cookie__:<token>.
        let expected = cookie_auth_header(&token);
        assert!(expected.starts_with("Basic "));
        assert!(credentials_match(&expected, &expected));
        assert!(!credentials_match("Basic d3Jvbmc=", &expected));
        assert!(!credentials_match("", &expected));
    }

    #[test]
    fn stop_flips_the_cancel_flag() {
        let snap = snap();
        let flag = Arc::new(AtomicBool::new(false));
        let (r, e) = dispatch("stop", &Value::Null, &snap, None, None, Some(&flag));
        assert!(e.is_none());
        assert_eq!(r, json!("Avila node stopping"));
        assert!(flag.load(Ordering::Relaxed));
        // Without a run loop the call reports honestly instead of lying.
        let (_, e) = dispatch("stop", &Value::Null, &snap, None, None, None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    /// Serves queries on a background thread over a real regtest
    /// chainstate — the same plumbing the sync loop runs.
    fn query_server(cs: Chainstate) -> QuerySender {
        let (tx, rx) = mpsc::channel::<ChainQuery>();
        let mut mgr: PeerManager<TcpStream> = PeerManager::new(8);
        let mut cs = cs;
        thread::spawn(move || {
            while let Ok(q) = rx.recv() {
                q.answer(&mut cs, &mut mgr);
            }
        });
        tx
    }

    #[test]
    fn chain_queries_answer_from_the_live_chainstate() {
        let cs = Chainstate::new(&Network::Regtest.params());
        let queries = query_server(cs);
        let snap = snap();

        let (r, e) = dispatch(
            "getblockhash",
            &json!([0]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        let genesis = r.as_str().unwrap().to_string();

        let (r, e) = dispatch(
            "getblockheader",
            &json!([genesis]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["height"], 0);
        assert_eq!(r["confirmations"], 1);
        assert_eq!(r["hash"], genesis);
        // Genesis is the active tip — no nextblockhash.
        assert!(r.get("nextblockhash").is_none());
        assert!(r.get("previousblockhash").is_none());

        // Non-verbose getblockheader returns the raw 80-byte header.
        let (r, e) = dispatch(
            "getblockheader",
            &json!([genesis, false]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        assert_eq!(r.as_str().unwrap().len(), 160);

        // The genesis header's body is never stored (genesis is never
        // connected), but `body()` synthesizes it from params — Core's
        // blk files always carry it, so getblock must serve it.
        let (r, e) = dispatch(
            "getblock",
            &json!([genesis, 1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["hash"], genesis);
        assert_eq!(r["height"], 0);
        assert_eq!(r["tx"][0].as_str().unwrap().len(), 64);

        // Unknown heights/hashes get Core's error codes, not nulls.
        let (_, e) = dispatch(
            "getblockhash",
            &json!([99]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getblockheader",
            &json!([BlockHash::from_bytes([9u8; 32]).to_string()]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_ADDRESS_OR_KEY);

        // gettxout on a nonexistent outpoint is null (like Core).
        let (_, e) = dispatch(
            "gettxout",
            &json!([Txid::from_bytes([1u8; 32]).to_string(), 0]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        let (r, _) = dispatch(
            "gettxout",
            &json!([Txid::from_bytes([1u8; 32]).to_string(), 0]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(r.is_null());

        // No txindex and not in the mempool → Core's -5.
        let (_, e) = dispatch(
            "getrawtransaction",
            &json!([Txid::from_bytes([1u8; 32]).to_string()]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_ADDRESS_OR_KEY);
    }

    #[test]
    fn core_shaped_fields_are_present() {
        let cs = Chainstate::new(&Network::Regtest.params());
        let queries = query_server(cs);
        let snap = snap();

        // getblockchaininfo carries Core's field set.
        let (r, e) = dispatch(
            "getblockchaininfo",
            &Value::Null,
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        for key in [
            "chain",
            "blocks",
            "headers",
            "bestblockhash",
            "bits",
            "target",
            "difficulty",
            "time",
            "mediantime",
            "verificationprogress",
            "initialblockdownload",
            "chainwork",
            "size_on_disk",
            "pruned",
            "warnings",
        ] {
            assert!(r.get(key).is_some(), "getblockchaininfo missing {key}");
        }
        assert_eq!(r["chain"], "regtest");

        // getmempoolinfo carries Core's counters.
        let (r, e) = dispatch(
            "getmempoolinfo",
            &Value::Null,
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        for key in [
            "loaded",
            "size",
            "bytes",
            "usage",
            "total_fee",
            "maxmempool",
            "mempoolminfee",
            "minrelaytxfee",
            "incrementalrelayfee",
            "fullrbf",
            "unbroadcastcount",
        ] {
            assert!(r.get(key).is_some(), "getmempoolinfo missing {key}");
        }
        // Core 29.x deployed defaults: 0.1 sat/vB floors + full-RBF.
        assert_eq!(r["incrementalrelayfee"].as_f64(), Some(1e-6));
        assert_eq!(r["minrelaytxfee"].as_f64(), Some(1e-6));
        assert_eq!(r["fullrbf"], Value::Bool(true));
        assert_eq!(r["maxmempool"].as_u64(), Some(300_000_000));

        // getblocktemplate carries the Core/Knots shape: mandatory
        // !segwit, taproot rule, proposal-only capabilities, empty
        // coinbaseaux, vb fields, tip+height longpollid, and the
        // zero-witness-root commitment every post-segwit block needs.
        let (r, e) = dispatch(
            "getblocktemplate",
            &json!([{"rules": ["segwit"]}]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["capabilities"], json!(["proposal"]));
        assert_eq!(r["rules"], json!(["csv", "!segwit", "taproot"]));
        assert_eq!(r["vbrequired"], 0);
        assert!(r.get("vbavailable").is_some());
        assert_eq!(r["coinbaseaux"], json!({}));
        assert_eq!(
            r["longpollid"],
            json!(format!(
                "{}{}",
                avila_consensus::params::Network::Regtest
                    .params()
                    .genesis_header
                    .hash(),
                1
            ))
        );
        let commitment = r["default_witness_commitment"].as_str().unwrap();
        assert!(
            commitment.starts_with("6a24aa21a9ed"),
            "missing the BIP141 commitment: {commitment}"
        );

        // getmininginfo reports the next-block retarget.
        let (r, e) = dispatch(
            "getmininginfo",
            &Value::Null,
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["chain"], "regtest");
        assert_eq!(r["next"]["height"], 1);
        assert!(r["next"]["target"].is_string());

        // An empty pool has no confirmation samples — Core returns a
        // result object with `errors`, not an RPC error.
        let (r, e) = dispatch(
            "estimatesmartfee",
            &json!([6]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        assert_eq!(
            r,
            json!({"errors": ["Insufficient data or no feerate found"], "blocks": 0})
        );

        // getnetworkinfo splits in/out connections.
        let (r, e) = dispatch(
            "getnetworkinfo",
            &Value::Null,
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["connections_in"], 0);
        assert_eq!(r["connections_out"], 0);
        assert_eq!(r["localservicesnames"], json!(["NETWORK", "WITNESS"]));
    }

    /// Every expected string below is verbatim Knots 29.3
    /// `decodescript` output on regtest — asm, desc (with checksum),
    /// type, and address all compared against the real thing.
    #[test]
    fn script_pubkey_json_matches_core_shapes() {
        use avila_consensus::transaction::Script;
        let params = Network::Regtest.params();
        let decode = |hexstr: &str| {
            let script = Script::new(avila_consensus::hex::decode(hexstr).unwrap());
            script_pubkey_json(&script, &params)
        };

        let p2pkh = decode("76a914ba602196720c6f0c47c823e106405d9b0dc71dc088ac");
        assert_eq!(p2pkh["type"], "pubkeyhash");
        assert_eq!(p2pkh["address"], "mxWR93hymS6qTPxA5oa9LrX6nUCEPnu9wm");
        assert_eq!(
            p2pkh["asm"],
            "OP_DUP OP_HASH160 ba602196720c6f0c47c823e106405d9b0dc71dc0 OP_EQUALVERIFY OP_CHECKSIG"
        );
        assert_eq!(
            p2pkh["desc"],
            "addr(mxWR93hymS6qTPxA5oa9LrX6nUCEPnu9wm)#3935e2kq"
        );

        let p2sh = decode("a914eb2940a3d86327415123af1dc3ff8d3e349af46487");
        assert_eq!(p2sh["type"], "scripthash");
        assert_eq!(p2sh["address"], "2NEgeCdxfyXSUB8D2TDez9WTC5YV3LJxE9i");
        assert_eq!(
            p2sh["desc"],
            "addr(2NEgeCdxfyXSUB8D2TDez9WTC5YV3LJxE9i)#957866pd"
        );

        let p2wpkh = decode("00142ef0abe149d195f81afe34f9c8a5b296947bb25d");
        assert_eq!(p2wpkh["type"], "witness_v0_keyhash");
        assert_eq!(
            p2wpkh["address"],
            "bcrt1q9mc2hc2f6x2lsxh7xnuu3fdjj628hvjatzgxcr"
        );
        assert_eq!(p2wpkh["asm"], "0 2ef0abe149d195f81afe34f9c8a5b296947bb25d");

        let p2wsh = decode("0020651d283f80f9673099142e0c4d7f4367e3bf87f3b6e75f3d00e17540d1f4f96f");
        assert_eq!(p2wsh["type"], "witness_v0_scripthash");
        assert_eq!(
            p2wsh["address"],
            "bcrt1qv5wjs0uql9nnpxg59cxy6l6rvl3mlplnkmn470gqu965p505l9hsvmeu5k"
        );

        let p2tr = decode("51201d4ade4c044494c4d01633a5595d9b5e1660f8ea81e60564c5377b3f8cc5a2fb");
        assert_eq!(p2tr["type"], "witness_v1_taproot");
        assert_eq!(
            p2tr["address"],
            "bcrt1pr49dunqygj2vf5qkxwj4jhvmtctxp782s8nq2ex9xaanlrx95tasaxw9kg"
        );
        assert_eq!(
            p2tr["asm"],
            "1 1d4ade4c044494c4d01633a5595d9b5e1660f8ea81e60564c5377b3f8cc5a2fb"
        );
        assert_eq!(
            p2tr["desc"],
            "rawtr(1d4ade4c044494c4d01633a5595d9b5e1660f8ea81e60564c5377b3f8cc5a2fb)#wt50qs67"
        );

        // Bare pubkey: no address, pk() descriptor.
        let p2pk = decode("2102aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac");
        assert_eq!(p2pk["type"], "pubkey");
        assert!(p2pk.get("address").is_none());
        assert_eq!(
            p2pk["desc"],
            "pk(02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)#rkg34naf"
        );

        // Bare 1-of-2 multisig: no address, multi() descriptor.
        let multi = decode(
            "512102aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
             2103bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb52ae",
        );
        assert_eq!(multi["type"], "multisig");
        assert!(multi.get("address").is_none());
        assert_eq!(
            multi["desc"],
            "multi(1,02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,\
03bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb)#wcrrdnej"
        );

        // An unknown witness program still gets an address (bech32m).
        let wunknown = decode("600228e0");
        assert_eq!(wunknown["type"], "witness_unknown");
        assert_eq!(wunknown["address"], "bcrt1s9rsqjg3vuy");
        assert_eq!(wunknown["asm"], "16 -24616");
        assert_eq!(wunknown["desc"], "addr(bcrt1s9rsqjg3vuy)#k0y40j9r");

        // OP_RETURN carries no address — desc is raw(hex).
        let nulldata = decode("6a0b68656c6c6f20776f726c64");
        assert_eq!(nulldata["type"], "nulldata");
        assert!(nulldata.get("address").is_none());
        assert_eq!(nulldata["asm"], "OP_RETURN 68656c6c6f20776f726c64");
        assert_eq!(nulldata["desc"], "raw(6a0b68656c6c6f20776f726c64)#hcyqe6dc");

        let empty = script_pubkey_json(&Script::new(Vec::new()), &params);
        assert_eq!(empty["type"], "nonstandard");
        assert_eq!(empty["asm"], "");
        assert_eq!(empty["desc"], "raw()#58lrscpx");

        // 0xff is OP_INVALIDOPCODE — a real opcode byte, not a
        // truncated push.
        let malformed = decode("51ff");
        assert_eq!(malformed["asm"], "1 OP_INVALIDOPCODE");
        assert_eq!(malformed["type"], "nonstandard");
        assert_eq!(malformed["desc"], "raw(51ff)#297em9yk");
    }

    /// `sendrawtransaction`'s deterministic paths — param validation,
    /// decode errors, and consensus rejects all carry Core's codes and
    /// reason strings (verified live against Knots 29.3).
    #[test]
    fn sendrawtransaction_error_paths() {
        let cs = Chainstate::new(&Network::Regtest.params());
        let queries = query_server(cs);
        let snap = snap();

        // Missing arg and negative maxfeerate fail before decoding.
        let (_, e) = dispatch(
            "sendrawtransaction",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMS);
        let (_, e) = dispatch(
            "sendrawtransaction",
            &json!(["00", -1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);

        // Not-hex and non-tx hex are deserialization errors.
        let (_, e) = dispatch(
            "sendrawtransaction",
            &json!(["zz"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        let (_, e) = dispatch(
            "sendrawtransaction",
            &json!(["00ff"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let err = e.unwrap();
        assert_eq!(err.0, RPC_DESERIALIZATION_ERROR);
        assert!(err.1.starts_with("TX decode failed"));

        // A coinbase is a consensus reject — Core's reason string, -26.
        let coinbase = "02000000010000000000000000000000000000000000000000000000000000\
        000000000000ffffffff0151ffffffff010000000000000000015100000000";
        let coinbase: String = coinbase.chars().filter(|c| !c.is_whitespace()).collect();
        let (_, e) = dispatch(
            "sendrawtransaction",
            &json!([coinbase]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let err = e.unwrap();
        assert_eq!(err.0, RPC_VERIFY_REJECTED);
        assert_eq!(err.1, "bad-cb-length");

        // Without the query channel the method reports honestly.
        let (_, e) = dispatch(
            "sendrawtransaction",
            &json!(["00"]),
            &snap,
            None,
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    /// `savemempool` — without a block store there is nowhere to write;
    /// the method reports the misc error rather than fabricate a path.
    #[test]
    fn savemempool_reports_missing_store() {
        let cs = Chainstate::new(&Network::Regtest.params());
        let queries = query_server(cs);
        let snap = snap();
        let (_, e) = dispatch(
            "savemempool",
            &Value::Null,
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch("savemempool", &Value::Null, &snap, None, None, None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    /// `getblockstats` — genesis is the simplest block with stats:
    /// subsidy 50 BTC, one tx, and zero *actual* UTXO delta (Core
    /// excludes genesis outputs from the actual counters).
    #[test]
    fn getblockstats_reports_genesis() {
        let cs = Chainstate::new(&Network::Regtest.params());
        let queries = query_server(cs);
        let snap = snap();
        let (r, e) = dispatch(
            "getblockstats",
            &json!([0]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        assert_eq!(r["subsidy"], json!(5_000_000_000i64));
        assert_eq!(r["txs"], json!(1));
        assert_eq!(r["utxo_increase_actual"], json!(0));
        assert_eq!(r["height"], json!(0));

        // The stats filter restricts emitted keys.
        let (r, e) = dispatch(
            "getblockstats",
            &json!([0, ["subsidy", "txs"]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        assert_eq!(r["txs"], json!(1));
        assert!(r.get("avgfee").is_none(), "filtered key must be absent");

        // Out-of-range height and malformed hash carry Core's wording.
        let (_, e) = dispatch(
            "getblockstats",
            &json!([99]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().1, "Target block height 99 after current tip 0");
        let (_, e) = dispatch(
            "getblockstats",
            &json!(["deadbeef"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap().1,
            "hash_or_height must be of length 64 (not 8, for 'deadbeef')"
        );
    }

    /// `getdeploymentinfo` — genesis-tip chainstate: regtest buries at
    /// h1 are already active (the flag describes the block *following*
    /// the queried one), always-active taproot reports active, and
    /// testdummy (start_time 0) is `defined` before its first window.
    #[test]
    fn getdeploymentinfo_reports_genesis_tip() {
        let cs = Chainstate::new(&Network::Regtest.params());
        let queries = query_server(cs);
        let snap = snap();
        let (r, e) = dispatch(
            "getdeploymentinfo",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        assert_eq!(r["height"], json!(0));
        let d = &r["deployments"];
        assert_eq!(
            d["bip34"],
            json!({"type":"buried","active":true,"height":1})
        );
        assert_eq!(
            d["segwit"],
            json!({"type":"buried","active":true,"height":0})
        );
        assert_eq!(d["taproot"]["type"], json!("bip9"));
        assert_eq!(d["taproot"]["active"], json!(true));
        assert_eq!(d["taproot"]["height"], json!(0));
        assert_eq!(d["taproot"]["bip9"]["status"], json!("active"));
        assert_eq!(d["testdummy"]["bip9"]["status"], json!("defined"));
        assert_eq!(d["testdummy"]["active"], json!(false));
        assert!(d["testdummy"].get("height").is_none());

        // A 64-hex unknown hash is Core's -5; malformed strings -8.
        let (_, e) = dispatch(
            "getdeploymentinfo",
            &json!(["ab".repeat(32)]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_INVALID_ADDRESS_OR_KEY, "Block not found".into())
        );
        let (_, e) = dispatch(
            "getdeploymentinfo",
            &json!(["deadbeef"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap().1,
            "blockhash must be of length 64 (not 8, for 'deadbeef')"
        );
        // Too many args → -1 + full help.
        let (_, e) = dispatch(
            "getdeploymentinfo",
            &json!(["ab".repeat(32), 1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_MISC_ERROR);
        assert!(msg.starts_with("getdeploymentinfo ( \"blockhash\" )"));
    }

    /// `gettxoutproof`/`verifytxoutproof` — the genesis coinbase is the
    /// only tx in the genesis block; the classic BIP37 proof and the
    /// `-1`-format witness proof round-trip.
    #[test]
    fn txoutproof_round_trips_genesis() {
        let params = Network::Regtest.params();
        let queries = query_server(Chainstate::new(&params));
        let snap = snap();
        let genesis = params.genesis_block().unwrap();
        let ghash = genesis.block_hash().to_string();
        let gtxid = genesis.transactions[0].txid().to_string();

        // Classic proof round-trips to the txid list.
        let (r, e) = dispatch(
            "gettxoutproof",
            &json!([[&gtxid], &ghash]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        let proof = r.as_str().unwrap().to_string();
        let (r, e) = dispatch(
            "verifytxoutproof",
            &json!([proof]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!([&gtxid]));

        // Genesis has no witness commitment → version -1 witness proof.
        let (r, e) = dispatch(
            "gettxoutproof",
            &json!([[&gtxid], &ghash, {"prove_witness": true}]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["proven"]["blockindex"], Value::Null);
        assert_eq!(r["proven"]["blockheight"], json!(0));
        assert_eq!(r["proven"]["tx"][0]["blockindex"], json!(0));
        let wproof = r["proof"].as_str().unwrap().to_string();
        assert!(wproof.starts_with("ffffffff"), "version -1 prefix");
        let (r, e) = dispatch(
            "verifytxoutproof",
            &json!([wproof, {"verify_witness": true}]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["blockheight"], json!(0));
        assert_eq!(r["confirmations"], json!(1));
        assert_eq!(r["tx"][0]["blockindex"], json!(0));
        // No witness data: the coinbase wtxid is its txid.
        assert_eq!(r["tx"][0]["wtxid"], json!(&gtxid));

        // A witness proof without the flag yields the empty list, and a
        // classic proof under the flag fails to deserialize — both like
        // Knots.
        let (r, e) = dispatch(
            "verifytxoutproof",
            &json!([wproof]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        assert_eq!(r, json!([]));
    }

    /// `gettxoutproof` error contract — Knots' exact codes/wording.
    #[test]
    fn txoutproof_error_contract() {
        let params = Network::Regtest.params();
        let queries = query_server(Chainstate::new(&params));
        let snap = snap();
        let genesis = params.genesis_block().unwrap();
        let ghash = genesis.block_hash().to_string();
        let gtxid = genesis.transactions[0].txid().to_string();

        let (_, e) = dispatch(
            "gettxoutproof",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch(
            "gettxoutproof",
            &json!([[]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (
                RPC_INVALID_PARAMETER,
                "Parameter 'txids' cannot be empty".into()
            )
        );
        let (_, e) = dispatch(
            "gettxoutproof",
            &json!([[&gtxid, &gtxid]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (
                RPC_INVALID_PARAMETER,
                format!("Invalid parameter, duplicated txid: {gtxid}")
            )
        );
        let (_, e) = dispatch(
            "gettxoutproof",
            &json!([[&gtxid], "ab".repeat(32)]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_INVALID_ADDRESS_OR_KEY, "Block not found".into())
        );
        let (_, e) = dispatch(
            "gettxoutproof",
            &json!([["ab".repeat(32)], &ghash]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (
                RPC_INVALID_ADDRESS_OR_KEY,
                "Not all transactions found in specified or retrieved block".into()
            )
        );
        // Truncated proof → -1 deserialization error.
        let (_, e) = dispatch(
            "verifytxoutproof",
            &json!(["00000030"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (
                RPC_MISC_ERROR,
                "DataStream::read(): end of data: iostream error".into()
            )
        );
        // A proof whose header doesn't resolve on the active chain.
        let mut header = genesis.header;
        header.nonce += 1;
        let mut bytes = header.encode().to_vec();
        avila_consensus::merkle::PartialMerkleTree::build(
            &[genesis.transactions[0].txid().to_bytes()],
            &[true],
        )
        .encode(&mut bytes);
        let (_, e) = dispatch(
            "verifytxoutproof",
            &json!([hex::encode(&bytes)]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (
                RPC_INVALID_ADDRESS_OR_KEY,
                "Block not found in chain".into()
            )
        );
    }

    /// `submitblock` — the mining loop end to end: a template-built
    /// block connects (Core returns null) and a resubmit reports
    /// "duplicate". Decode failures are -22 like Core.
    #[test]
    fn submitblock_connects_and_reports_core_status() {
        let params = Network::Regtest.params();
        // A genesis-tip regtest chainstate is deterministic — the block
        // built here connects identically on the query server's copy.
        let mine_cs = Chainstate::new(&params);
        let pool = avila_mempool::Mempool::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let mut block = pool
            .build_template(
                &mine_cs,
                Script::new(vec![avila_consensus::script::OP_1]),
                now,
            )
            .unwrap()
            .block;
        // Regtest's target is near-maximal — a few nonces at most.
        while avila_consensus::pow::check_proof_of_work(
            &block.block_hash(),
            block.header.bits,
            &params,
        )
        .is_err()
        {
            block.header.nonce += 1;
        }
        let hexdata = hex::encode(&block.encode());

        let queries = query_server(Chainstate::new(&params));
        let snap = snap();
        let (r, e) = dispatch(
            "submitblock",
            &json!([hexdata]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null); // connected — Core's null
        let (r, e) = dispatch(
            "submitblock",
            &json!([hexdata]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!("duplicate"));

        // Decode failures carry Core's -22.
        let (_, e) = dispatch(
            "submitblock",
            &json!(["aabb"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        let (_, e) = dispatch("submitblock", &json!([]), &snap, Some(&queries), None, None);
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMS);
    }

    /// `submitheader` — a known header returns null, an orphan carries
    /// Core's "Must submit previous header" -25, decode failures are -22.
    #[test]
    fn submitheader_reports_core_status() {
        let params = Network::Regtest.params();
        let queries = query_server(Chainstate::new(&params));
        let snap = snap();

        // A valid-PoW header with an unknown parent: regtest's target
        // is near-maximal so a few nonces suffice.
        let unknown = BlockHash::from_bytes([0x42; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let bits = params.genesis_header.bits;
        let mut header = avila_consensus::header::BlockHeader {
            version: 0x2000_0000,
            prev_block_hash: unknown,
            merkle_root: params.genesis_header.merkle_root,
            time: now,
            bits,
            nonce: 0,
        };
        while avila_consensus::pow::check_proof_of_work(&header.hash(), bits, &params).is_err() {
            header.nonce += 1;
        }
        let hexdata = hex::encode(&header.encode());
        let (_, e) = dispatch(
            "submitheader",
            &json!([hexdata]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_VERIFY_ERROR);
        assert_eq!(
            msg,
            format!("Must submit previous header ({unknown}) first")
        );

        // Genesis's own header is already known → null, like Core.
        let genesis = hex::encode(&params.genesis_header.encode());
        let (r, e) = dispatch(
            "submitheader",
            &json!([genesis]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);

        let (_, e) = dispatch(
            "submitheader",
            &json!(["zz"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
    }

    /// `generatetoaddress` mines real blocks to a decoded address and
    /// `generateblock` covers the tx-resolution error paths. Both
    /// grow the chain — the query server's state advances.
    #[test]
    fn generate_methods_mine_and_validate() {
        let params = Network::Regtest.params();
        let queries = query_server(Chainstate::new(&params));
        let snap = snap();
        let addr = "bcrt1q9mc2hc2f6x2lsxh7xnuu3fdjj628hvjatzgxcr"; // real regtest P2WPKH

        let (r, e) = dispatch(
            "generatetoaddress",
            &json!([1, addr]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        let hashes = r.as_array().unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].as_str().unwrap().len(), 64);

        // Bad address → Core's -5.
        let (_, e) = dispatch(
            "generatetoaddress",
            &json!([1, "notanaddress"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_ADDRESS_OR_KEY);

        // generateblock: coinbase-only block pays a descriptor.
        let (r, e) = dispatch(
            "generateblock",
            &json!([format!("addr({addr})"), []]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["hash"].as_str().unwrap().len(), 64);

        // Unknown txid → -5 "not in mempool"; bad hex → -22.
        let (_, e) = dispatch(
            "generateblock",
            &json!([addr, ["aa".repeat(32)]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_INVALID_ADDRESS_OR_KEY);
        assert!(msg.contains("not in mempool"), "{msg}");
        let (_, e) = dispatch(
            "generateblock",
            &json!([addr, ["zz"]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        // Bad output → -5.
        let (_, e) = dispatch(
            "generateblock",
            &json!(["zzz", []]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_ADDRESS_OR_KEY);
    }

    /// `decoderawtransaction` — the regtest genesis coinbase decodes
    /// in Core's TxToUniv shape (no `hex` echo), each `iswitness`
    /// spelling works, and every error path carries Core's code.
    #[test]
    fn decoderawtransaction_matches_core_shape() {
        let params = Network::Regtest.params();
        let queries = query_server(Chainstate::new(&params));
        let snap = snap();
        let cb_hex = hex::encode(&params.genesis_block().unwrap().transactions[0].encode());
        let cb_txid = params.genesis_block().unwrap().transactions[0]
            .txid()
            .to_string();

        for p in [
            json!([cb_hex]),
            json!([cb_hex, true]),
            json!([cb_hex, false]),
        ] {
            let (r, e) = dispatch(
                "decoderawtransaction",
                &p,
                &snap,
                Some(&queries),
                None,
                None,
            );
            assert!(e.is_none(), "{e:?}");
            assert_eq!(r["txid"], json!(cb_txid));
            assert!(r.get("hex").is_none(), "decoderawtransaction omits hex");
            assert!(r.get("blockhash").is_none());
            assert_eq!(r["vin"][0]["coinbase"].as_str().unwrap().len() % 2, 0);
        }

        // Bad hex / undecodable bytes / wrong-type iswitness / missing
        // or excess args all carry Core's codes.
        let (_, e) = dispatch(
            "decoderawtransaction",
            &json!(["zz"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        let (_, e) = dispatch(
            "decoderawtransaction",
            &json!(["00"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        let (_, e) = dispatch(
            "decoderawtransaction",
            &json!([cb_hex, 2]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 2 (iswitness)"), "{msg}");
        let (_, e) = dispatch(
            "decoderawtransaction",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch(
            "decoderawtransaction",
            &json!([cb_hex, true, 1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    /// `getindexinfo` — `{}` without `-txindex`, the Core status object
    /// with it, and the name filter gates the output.
    #[test]
    fn getindexinfo_reflects_txindex_state() {
        let snap = snap();
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let (r, e) = dispatch(
            "getindexinfo",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        assert_eq!(r, json!({}));

        let mut cs = Chainstate::new(&Network::Regtest.params());
        cs.enable_txindex(None).unwrap();
        let queries = query_server(cs);
        let (r, e) = dispatch(
            "getindexinfo",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        assert_eq!(r["txindex"]["synced"], json!(true));
        assert_eq!(r["txindex"]["best_block_height"], json!(0));

        // The name filter: "txindex" keeps it, anything else empties.
        let (r, _) = dispatch(
            "getindexinfo",
            &json!(["txindex"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(r.get("txindex").is_some());
        let (r, _) = dispatch(
            "getindexinfo",
            &json!(["coinstatsindex"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r, json!({}));
        // Non-string name → Core's -3; extra args → the -1 help throw.
        let (_, e) = dispatch(
            "getindexinfo",
            &json!([5]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);
        let (_, e) = dispatch(
            "getindexinfo",
            &json!(["a", "b"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    /// `gettxspendingprevout` — well-formed queries echo the inputs and
    /// every malformed input carries Core's exact error code.
    #[test]
    fn gettxspendingprevout_validates_core_style() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let txid = "04".repeat(32);

        // Nothing in the pool spends it → the entry echoes without
        // `spendingtxid`.
        let (r, e) = dispatch(
            "gettxspendingprevout",
            &json!([[{"txid": txid, "vout": 0}]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(
            r,
            json!([{"txid": txid, "vout": 0}]),
            "unspent output must omit spendingtxid"
        );

        // Core's error taxonomy: -1 help for absent/oversized args,
        // -3 for type errors and missing fields, -8 for the
        // outputs-empty / negative-vout / bad-txid gates, -1 for
        // integer range.
        for (p, code) in [
            (json!([]), RPC_MISC_ERROR),
            (
                json!([[{"txid": txid, "vout": 0}], [{"txid": txid, "vout": 1}]]),
                RPC_MISC_ERROR,
            ),
            (json!(["notarray"]), RPC_TYPE_ERROR),
            (json!([[5]]), RPC_TYPE_ERROR),
            (json!([[{"vout": 0}]]), RPC_TYPE_ERROR),
            (json!([[{"txid": 5, "vout": 0}]]), RPC_TYPE_ERROR),
            (json!([[{"txid": txid}]]), RPC_TYPE_ERROR),
            (json!([[{"txid": txid, "vout": "0"}]]), RPC_TYPE_ERROR),
            (json!([[]]), RPC_INVALID_PARAMETER),
            (json!([[{"txid": "zz", "vout": 0}]]), RPC_INVALID_PARAMETER),
            (json!([[{"txid": txid, "vout": -1}]]), RPC_INVALID_PARAMETER),
            (json!([[{"txid": txid, "vout": 1.5}]]), RPC_MISC_ERROR),
            (
                json!([[{"txid": txid, "vout": 4_000_000_000i64}]]),
                RPC_MISC_ERROR,
            ),
        ] {
            let (_, e) = dispatch(
                "gettxspendingprevout",
                &p,
                &snap,
                Some(&queries),
                None,
                None,
            );
            assert_eq!(e.unwrap().0, code, "params {p}");
        }
    }

    /// `getnetworkhashps` — on a genesis-only chain every window
    /// degenerates to 0, and the arg validation is Core's: -3 wrong
    /// type, -1 integer range, -8 for nblocks 0/<-1 and for heights
    /// past the tip or below -1.
    #[test]
    fn getnetworkhashps_validates_and_reports() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        // Genesis-only chain: pb->nHeight == 0 → 0, like Core.
        let (r, e) = dispatch(
            "getnetworkhashps",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!(0));
        let (r, _) = dispatch(
            "getnetworkhashps",
            &json!([120, 0]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r, json!(0));

        for (p, code) in [
            (json!(["x"]), RPC_TYPE_ERROR),
            (json!([120, "x"]), RPC_TYPE_ERROR),
            (json!([1.5]), RPC_MISC_ERROR),
            (json!([120, 1.5]), RPC_MISC_ERROR),
            (json!([0]), RPC_INVALID_PARAMETER),
            (json!([-2]), RPC_INVALID_PARAMETER),
            (json!([120, -2]), RPC_INVALID_PARAMETER),
            (json!([120, 1]), RPC_INVALID_PARAMETER), // past the h0 tip
            (json!([1, 2, 3]), RPC_MISC_ERROR),
        ] {
            let (_, e) = dispatch("getnetworkhashps", &p, &snap, Some(&queries), None, None);
            assert_eq!(e.unwrap().0, code, "params {p}");
        }
    }

    /// `getnettotals` — Core's shape: cumulative byte counters, wall
    /// `timemillis`, and the unlimited `uploadtarget` block. Any arg
    /// is Core's -1 help throw.
    #[test]
    fn getnettotals_reports_cumulative_counters() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let (r, e) = dispatch(
            "getnettotals",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["totalbytesrecv"], json!(0));
        assert_eq!(r["totalbytessent"], json!(0));
        assert!(r["timemillis"].as_u64().unwrap() > 0);
        assert_eq!(r["uploadtarget"]["target"], json!(0));
        assert_eq!(r["uploadtarget"]["timeframe"], json!(86400));
        assert_eq!(r["uploadtarget"]["serve_historical_blocks"], json!(true));
        let (_, e) = dispatch(
            "getnettotals",
            &json!([1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    /// `ping`/`disconnectnode`/`addnode`/`setnetworkactive` — the
    /// network-admin dispatch contract over a peer-less manager.
    #[test]
    fn network_admin_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        // ping: no args → null; any arg → -1 + help.
        let (r, e) = dispatch("ping", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
        let (_, e) = dispatch("ping", &json!([1]), &snap, Some(&queries), None, None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);

        // disconnectnode: no match → -29; both ids → -32602; bad
        // subnet → -8; bad types → -3.
        let (_, e) = dispatch(
            "disconnectnode",
            &json!(["", 999]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_CLIENT_NODE_NOT_CONNECTED);
        let (_, e) = dispatch(
            "disconnectnode",
            &json!(["1.2.3.4:5", 6]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMS);
        let (_, e) = dispatch(
            "disconnectnode",
            &json!(["notanip/zz", ""]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);
        let (_, e) = dispatch(
            "disconnectnode",
            &json!(["notanip/33"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);

        // addnode: add → null; duplicate → -23; remove → null;
        // second remove → -24; bad command/type → -1/-8/-3.
        let (r, e) = dispatch(
            "addnode",
            &json!(["1.2.3.4:8333", "add"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
        let (_, e) = dispatch(
            "addnode",
            &json!(["1.2.3.4:8333", "add"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_CLIENT_NODE_ALREADY_ADDED);
        let (_, e) = dispatch(
            "addnode",
            &json!(["1.2.3.4:8333", "add", "feeler"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (r, e) = dispatch(
            "addnode",
            &json!(["1.2.3.4:8333", "remove"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
        let (_, e) = dispatch(
            "addnode",
            &json!(["1.2.3.4:8333", "remove"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_CLIENT_NODE_NOT_ADDED);
        let (_, e) = dispatch(
            "addnode",
            &json!(["x", "add", "bogus_type"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "addnode",
            &json!(["x", "add", true]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);

        // setnetworkactive: returns the post-set state; toggling with
        // no peers is a no-op; non-bool → -3; missing → -1.
        let (r, e) = dispatch(
            "setnetworkactive",
            &json!([false]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!(false));
        let (r, e) = dispatch(
            "setnetworkactive",
            &json!([true]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!(true));
        let (_, e) = dispatch(
            "setnetworkactive",
            &json!([5]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);
        let (_, e) = dispatch(
            "setnetworkactive",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    /// `setban`/`listbanned`/`clearbanned` — the banlist lifecycle on a
    /// real `PeerManager`, with Core's validation order (command help
    /// throw before the subnet parse) and error codes.
    #[test]
    fn ban_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        // Empty list to start; listbanned/clearbanned take no params.
        let (r, e) = dispatch("listbanned", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!([]));
        let (_, e) = dispatch("listbanned", &json!([1]), &snap, Some(&queries), None, None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (r, e) = dispatch("clearbanned", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
        let (_, e) = dispatch(
            "clearbanned",
            &json!([1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);

        // add: null; the subnet normalizes to its prefix and lists
        // with Core's fields (default 24h duration).
        let (r, e) = dispatch(
            "setban",
            &json!(["10.1.2.3/16", "add"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
        let (r, e) = dispatch("listbanned", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r.as_array().unwrap().len(), 1);
        assert_eq!(r[0]["address"], json!("10.1.0.0/16"));
        assert_eq!(
            r[0]["ban_duration"],
            json!(avila_p2p::banman::DEFAULT_BANTIME)
        );
        for k in ["ban_created", "banned_until", "time_remaining"] {
            assert!(r[0][k].is_i64(), "{k}: {r}");
        }

        // Re-adding the active subnet → -23; removing → null; a
        // second remove → -30 "not previously manually banned".
        let (_, e) = dispatch(
            "setban",
            &json!(["10.1.0.0/16", "add"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_CLIENT_NODE_ALREADY_ADDED);
        let (r, e) = dispatch(
            "setban",
            &json!(["10.1.0.0/16", "remove"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
        let (_, e) = dispatch(
            "setban",
            &json!(["10.1.0.0/16", "remove"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_CLIENT_INVALID_IP_OR_SUBNET);
        let (r, e) = dispatch("listbanned", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!([]));

        // Absolute bantime in the past → -8; in the future → ok and
        // `banned_until` equals it exactly.
        let now = epoch_secs();
        let (_, e) = dispatch(
            "setban",
            &json!(["2001:db8::/32", "add", now - 10, true]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (r, e) = dispatch(
            "setban",
            &json!(["2001:db8::/32", "add", now + 3600, true]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
        let (r, e) = dispatch("listbanned", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r[0]["address"], json!("2001:db8::/32"));
        assert_eq!(r[0]["banned_until"], json!(now + 3600));

        // Validation order: bad command → -1 help even with a bad
        // subnet; bad subnet + good command → -30; type errors → -3;
        // non-integral bantime → -1 "out of range"; arity → -1.
        for (p, code) in [
            (json!(["999.1.1.1", "bogus"]), RPC_MISC_ERROR),
            (json!(["999.1.1.1", "add"]), RPC_CLIENT_INVALID_IP_OR_SUBNET),
            (json!(["10.0.0.1", "bogus"]), RPC_MISC_ERROR),
            (json!([5, "add"]), RPC_TYPE_ERROR),
            (json!(["10.0.0.1", 5]), RPC_TYPE_ERROR),
            (json!(["10.0.0.1", "add", "x"]), RPC_TYPE_ERROR),
            (json!(["10.0.0.1", "add", 100, "x"]), RPC_TYPE_ERROR),
            (json!(["10.0.0.1", "add", 1.5]), RPC_MISC_ERROR),
            (json!([]), RPC_MISC_ERROR),
            (json!(["10.0.0.1"]), RPC_MISC_ERROR),
            (
                json!(["10.0.0.1", "add", 0, false, "extra"]),
                RPC_MISC_ERROR,
            ),
        ] {
            let (_, e) = dispatch("setban", &p, &snap, Some(&queries), None, None);
            assert_eq!(e.unwrap().0, code, "params {p}");
        }

        // clearbanned empties the list.
        let (r, e) = dispatch("clearbanned", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
        let (r, e) = dispatch("listbanned", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!([]));
    }

    /// `verifychain` — the bool result plus Core's arg contract: no
    /// range gate on checklevel/nblocks, -3 type errors per position,
    /// -1 for non-integral or excess args.
    #[test]
    fn verifychain_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        // Genesis-only chain: every level/depth verifies (vacuous).
        for p in [
            json!([]),
            json!([3]),
            json!([4, 10]),
            json!([0, 0]),
            json!([5]),
            json!([-1]),
            json!([null, null]),
        ] {
            let (r, e) = dispatch("verifychain", &p, &snap, Some(&queries), None, None);
            assert!(e.is_none(), "{p}: {e:?}");
            assert_eq!(r, json!(true), "{p}");
        }
        for (p, code) in [
            (json!(["x"]), RPC_TYPE_ERROR),
            (json!([3, "x"]), RPC_TYPE_ERROR),
            (json!([1.5]), RPC_MISC_ERROR),
            (json!([4, 1.5]), RPC_MISC_ERROR),
            (json!([3, 10, "x"]), RPC_MISC_ERROR),
        ] {
            let (_, e) = dispatch("verifychain", &p, &snap, Some(&queries), None, None);
            assert_eq!(e.unwrap().0, code, "params {p}");
        }
    }

    /// `getaddrmaninfo` — Core's fixed network keys each carrying
    /// {new, tried, total}, plus the help throw on any arg.
    #[test]
    fn getaddrmaninfo_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        let (r, e) = dispatch(
            "getaddrmaninfo",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        for net in ["ipv4", "ipv6", "onion", "i2p", "cjdns", "all_networks"] {
            assert_eq!(r[net], json!({"new": 0, "tried": 0, "total": 0}), "{net}");
        }
        let (_, e) = dispatch(
            "getaddrmaninfo",
            &json!([1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);

        // A seeded entry lands under its network.
        let (r, e) = dispatch(
            "addpeeraddress",
            &json!(["1.2.3.4", 8333, true]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["success"], json!(true));
        let (r, e) = dispatch(
            "getaddrmaninfo",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["ipv4"], json!({"new": 0, "tried": 1, "total": 1}));
        assert_eq!(r["all_networks"], json!({"new": 0, "tried": 1, "total": 1}));
    }

    /// `preciousblock` — ParseHashV errors, `-5` for a hash outside
    /// the index, `null` on success (genesis is in the index, so
    /// marking it is a valid no-op).
    #[test]
    fn preciousblock_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        // Missing/extra args → -1 + help; non-string → -3 (Core's
        // Wrong-type "Position 1 (blockhash)" message).
        let (_, e) = dispatch(
            "preciousblock",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch(
            "preciousblock",
            &json!([7]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);
        let (_, e) = dispatch(
            "preciousblock",
            &json!(["00", "x"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);

        // ParseHashV: wrong length → -8, bad hex → -8.
        let (_, e) = dispatch(
            "preciousblock",
            &json!(["00"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_INVALID_PARAMETER);
        assert!(msg.contains("length 64 (not 2"), "{msg}");

        // A well-formed hash with no index entry → -5 Block not found.
        let unknown = "00".repeat(32);
        let (_, e) = dispatch(
            "preciousblock",
            &json!([unknown]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_INVALID_ADDRESS_OR_KEY, "Block not found".to_string())
        );

        // Genesis is in the index — marking it returns null.
        let (r, e) = dispatch(
            "getblockhash",
            &json!([0]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none());
        let genesis = r.as_str().unwrap().to_string();
        let (r, e) = dispatch(
            "preciousblock",
            &json!([genesis]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);
    }

    /// `prioritisetransaction` — Core 29.4's validation order: exactly
    /// three positional args, a collected -3 type list, ParseHashV on
    /// the txid, getInt<int64> on fee_delta, then the zero-dummy
    /// compatibility check. Unknown txids succeed — the delta waits in
    /// the pool's map for admission.
    #[test]
    fn prioritisetransaction_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let txid = "00".repeat(32);

        // Arity — fewer than 3 args or extra args → -1 + help.
        for p in [
            json!([]),
            json!([txid]),
            json!([txid, 0]),
            json!([txid, 0, 0, 0]),
        ] {
            let (_, e) = dispatch(
                "prioritisetransaction",
                &p,
                &snap,
                Some(&queries),
                None,
                None,
            );
            let (code, msg) = e.unwrap();
            assert_eq!(code, RPC_MISC_ERROR, "{p}");
            assert!(msg.starts_with("prioritisetransaction"), "{msg}");
        }

        // The type pass collects every bad position into one list.
        let (_, e) = dispatch(
            "prioritisetransaction",
            &json!([7, "x", "y"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (txid)"), "{msg}");
        assert!(msg.contains("Position 2 (dummy)"), "{msg}");
        assert!(msg.contains("Position 3 (fee_delta)"), "{msg}");

        // Body order: txid format → -8, then fee_delta getInt → -1,
        // then a nonzero dummy → -8.
        let (_, e) = dispatch(
            "prioritisetransaction",
            &json!(["00", 0, 100]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "prioritisetransaction",
            &json!([txid, 0, 1.5]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_MISC_ERROR, "JSON integer out of range".to_string())
        );
        let (_, e) = dispatch(
            "prioritisetransaction",
            &json!([txid, 5, 100]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_INVALID_PARAMETER);
        assert!(msg.contains("dummy argument"), "{msg}");

        // Unknown txid, dummy 0 and dummy null → true.
        for p in [
            json!([txid, 0, 100]),
            json!([txid, 0.0, -50]),
            json!([txid, null, 100]),
        ] {
            let (r, e) = dispatch(
                "prioritisetransaction",
                &p,
                &snap,
                Some(&queries),
                None,
                None,
            );
            assert!(e.is_none(), "{p}: {e:?}");
            assert_eq!(r, json!(true), "{p}");
        }
    }

    /// `getblockfrompeer` — Core 29.4's order: exactly two args, the
    /// collected -3 type list, ParseHashV, getInt<int64>, then
    /// "Block header missing" → "Block already downloaded" →
    /// "Peer does not exist". The fixture has no peers, so the last
    /// check is the terminal one; the scheduling path is exercised
    /// live and by `fetch_block`'s own test.
    #[test]
    fn getblockfrompeer_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let hash = "00".repeat(32);

        for p in [json!([]), json!([hash]), json!([hash, 0, 0])] {
            let (_, e) = dispatch("getblockfrompeer", &p, &snap, Some(&queries), None, None);
            let (code, msg) = e.unwrap();
            assert_eq!(code, RPC_MISC_ERROR, "{p}");
            assert!(msg.starts_with("getblockfrompeer"), "{msg}");
        }

        // Both positions wrong-typed → the collected two-line list.
        let (_, e) = dispatch(
            "getblockfrompeer",
            &json!([7, "x"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (blockhash)"), "{msg}");
        assert!(msg.contains("Position 2 (peer_id)"), "{msg}");

        // ParseHashV precedes the peer_id getInt.
        let (_, e) = dispatch(
            "getblockfrompeer",
            &json!(["00", 1.5]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getblockfrompeer",
            &json!([hash, 1.5]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_MISC_ERROR, "JSON integer out of range".to_string())
        );

        // An unknown well-formed hash → "Block header missing".
        let (_, e) = dispatch(
            "getblockfrompeer",
            &json!([hash, 0]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_MISC_ERROR, "Block header missing".to_string())
        );

        // Genesis is downloaded (synthesized body) → "already
        // downloaded" beats the peer check.
        let (r, _) = dispatch(
            "getblockhash",
            &json!([0]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let genesis = r.as_str().unwrap().to_string();
        let (_, e) = dispatch(
            "getblockfrompeer",
            &json!([genesis, 9999]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_MISC_ERROR, "Block already downloaded".to_string())
        );
    }

    /// `waitforblock`/`waitforblockheight`/`waitfornewblock` — Core
    /// 29.4's validation order (arity → collected -3 list → parse) and
    /// the shared timeout contract: null/missing → forever, non-integral
    /// → -1, negative → -1 "Negative timeout". Immediate and timed-out
    /// waits both answer `{hash, height}` of the tip.
    #[test]
    fn waitforblock_family_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let waiters = Arc::new(BlockWaiters::new());
        let d = |m, p: Value| dispatch(m, &p, &snap, Some(&queries), Some(&waiters), None);
        let hash = "00".repeat(32);

        // Arity → -1 + verbatim help.
        for (m, p) in [
            ("waitforblock", json!([])),
            ("waitforblock", json!([hash, 0, 0])),
            ("waitforblockheight", json!([])),
            ("waitforblockheight", json!([1, 0, 0])),
            ("waitfornewblock", json!([1, 2])),
        ] {
            let (_, e) = d(m, p.clone());
            let (code, msg) = e.unwrap();
            assert_eq!(code, RPC_MISC_ERROR, "{m} {p}");
            assert!(msg.starts_with(m), "{m}: {msg}");
        }

        // Collected -3 type lists — all bad positions reported at once.
        let (_, e) = d("waitforblock", json!([7, "x"]));
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (blockhash)"), "{msg}");
        assert!(msg.contains("Position 2 (timeout)"), "{msg}");
        let (_, e) = d("waitforblockheight", json!(["x", "x"]));
        let (_, msg) = e.unwrap();
        assert!(msg.contains("Position 1 (height)"), "{msg}");
        assert!(msg.contains("Position 2 (timeout)"), "{msg}");
        let (_, e) = d("waitfornewblock", json!(["x"]));
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (timeout)"), "{msg}");

        // ParseHashV precedes the timeout getInt; non-integral ints and
        // negatives get Core's -1s.
        let (_, e) = d("waitforblock", json!(["00", 1.5]));
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        for p in [json!([hash, 1.5]), json!([hash, -1])] {
            let (_, e) = d("waitforblock", p);
            assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        }
        let (_, e) = d("waitforblockheight", json!([3_000_000_000i64, 1]));
        assert_eq!(
            e.unwrap(),
            (RPC_MISC_ERROR, "JSON integer out of range".to_string())
        );
        let (_, e) = d("waitfornewblock", json!([-1]));
        assert_eq!(e.unwrap(), (RPC_MISC_ERROR, "Negative timeout".to_string()));

        // A target already reached answers instantly — genesis is a
        // synthesized body and height -1 is already past.
        let (r, _) = d("getblockhash", json!([0]));
        let genesis = r.as_str().unwrap().to_string();
        for (m, p) in [
            ("waitforblock", json!([genesis, 100])),
            ("waitforblockheight", json!([-5, 100])),
            ("waitforblockheight", json!([0, 100])),
        ] {
            let (r, e) = d(m, p.clone());
            assert!(e.is_none(), "{m} {p}: {e:?}");
            assert_eq!(r["height"], 0, "{m} {p}");
            assert!(r["hash"].is_string(), "{m} {p}");
        }

        // Unsatisfied waits block for the timeout then answer the tip.
        let t0 = Instant::now();
        let (r, e) = d("waitforblockheight", json!([9999, 60]));
        assert!(t0.elapsed() >= Duration::from_millis(55));
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["height"], 0);
        let t0 = Instant::now();
        let (r, e) = d("waitfornewblock", json!([60]));
        assert!(t0.elapsed() >= Duration::from_millis(55));
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["height"], 0);
        let (r, e) = d("waitforblock", json!([hash, 60]));
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["height"], 0);
    }

    /// `createrawtransaction` — Core's `ConstructTransaction` contract:
    /// arity/help, the union-typed `outputs` gap in the collected type
    /// list, input field order, sequence defaults, and the output
    /// forms including `data` and duplicate checks.
    #[test]
    fn createrawtransaction_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let d = |p: Value| {
            dispatch(
                "createrawtransaction",
                &p,
                &snap,
                Some(&queries),
                None,
                None,
            )
        };
        let txid = "ab".repeat(32);
        let addr = "bcrt1q4474gjxvqsq7k5dsvejgfuh8u0qlnqq8djekgk";

        // Arity — required inputs+outputs, at most 4 args.
        for p in [json!([]), json!([[]]), json!([[], [], 0, true, 5])] {
            let (code, msg) = d(p.clone()).1.unwrap();
            assert_eq!(code, RPC_MISC_ERROR, "{p}");
            assert!(msg.starts_with("createrawtransaction"), "{msg}");
        }

        // Collected -3 list: inputs not an array, locktime and
        // replaceable wrong — `outputs` is union-typed and skipped.
        let (code, msg) = d(json!([7, "x", "x", "x"])).1.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (inputs)"), "{msg}");
        assert!(!msg.contains("Position 2"), "{msg}");
        assert!(msg.contains("Position 3 (locktime)"), "{msg}");
        assert!(msg.contains("Position 4 (replaceable)"), "{msg}");

        // Input element checks — bare -3 for non-objects and bad txid
        // types, ParseHashV for bad hashes, vout errors in order.
        let (code, msg) = d(json!([[7], [{"data": "aa"}]])).1.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert_eq!(
            msg,
            "JSON value of type number is not of expected type object"
        );
        let (code, msg) = d(json!([[{}], [{"data": "aa"}]])).1.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert_eq!(
            msg,
            "JSON value of type null is not of expected type string"
        );
        let (code, msg) = d(json!([[{"txid": "xx", "vout": 0}], [{"data": "aa"}]]))
            .1
            .unwrap();
        assert_eq!(code, RPC_INVALID_PARAMETER);
        assert!(msg.contains("txid must be of length 64"), "{msg}");
        for (input, expect) in [
            (json!({"txid": txid}), "Invalid parameter, missing vout key"),
            (
                json!({"txid": txid, "vout": "x"}),
                "Invalid parameter, missing vout key",
            ),
            (
                json!({"txid": txid, "vout": -1}),
                "Invalid parameter, vout cannot be negative",
            ),
        ] {
            let (code, msg) = d(json!([[input], [{"data": "aa"}]])).1.unwrap();
            assert_eq!((code, msg), (RPC_INVALID_PARAMETER, expect.to_string()));
        }
        for vout in [json!(1.5), json!(4_294_967_295u64)] {
            let (_, e) = d(json!([[{"txid": txid, "vout": vout}], [{"data": "aa"}]]));
            assert_eq!(
                e.unwrap(),
                (RPC_MISC_ERROR, "JSON integer out of range".to_string())
            );
        }

        // Sequence: non-numeric values are ignored (treated as
        // missing), out-of-range is -8, non-integral -1.
        let (_, e) = d(json!([[{"txid": txid, "vout": 0, "sequence": 1.5}], [{"data": "aa"}]]));
        assert_eq!(
            e.unwrap(),
            (RPC_MISC_ERROR, "JSON integer out of range".to_string())
        );
        for seq in [json!(-1), json!(4_294_967_296u64)] {
            let (_, e) = d(json!([[{"txid": txid, "vout": 0, "sequence": seq}], [{"data": "aa"}]]));
            assert_eq!(
                e.unwrap(),
                (
                    RPC_INVALID_PARAMETER,
                    "Invalid parameter, sequence number is out of range".to_string()
                )
            );
        }

        // Outputs normalization — null, scalar, non-object element,
        // multi-pair object, duplicate data.
        for (outputs, expect) in [
            (
                Value::Null,
                "Invalid parameter, output argument must be non-null",
            ),
            (
                json!([7]),
                "Invalid parameter, key-value pair not an object as expected",
            ),
            (
                json!([{}]),
                "Invalid parameter, key-value pair must contain exactly one key",
            ),
            (
                json!([{"data": "aa"}, {"data": "bb"}]),
                "Invalid parameter, duplicate key: data",
            ),
        ] {
            let (code, msg) = d(json!([[{"txid": txid, "vout": 0}], outputs])).1.unwrap();
            assert_eq!((code, msg), (RPC_INVALID_PARAMETER, expect.to_string()));
        }
        let (code, msg) = d(json!([[{"txid": txid, "vout": 0}], "x"])).1.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert_eq!(
            msg,
            "JSON value of type string is not of expected type array"
        );

        // The data value stringifies scalars then requires hex.
        let (code, msg) = d(json!([[{"txid": txid, "vout": 0}], [{"data": 7}]]))
            .1
            .unwrap();
        assert_eq!(
            (code, msg),
            (
                RPC_INVALID_PARAMETER,
                "Data must be hexadecimal string (not '7')".to_string()
            )
        );

        // Amounts parse before the address validates — the "data2"
        // key is an address, so a garbage amount errors first.
        for (key, val, expect) in [
            ("data2", json!("x"), "Invalid amount"),
            (addr, json!(-0.1), "Amount out of range"),
            (addr, json!(21_000_001), "Amount out of range"),
            (addr, json!(0.000000001), "Invalid amount"),
            (addr, json!(true), "Amount is not a number or string"),
        ] {
            let (_, e) = d(json!([[{"txid": txid, "vout": 0}], [{key: val}]]));
            assert_eq!(
                e.unwrap(),
                (RPC_TYPE_ERROR, expect.to_string()),
                "{key}: {val}"
            );
        }
        for (key, expect) in [
            ("data2", "Invalid Bitcoin address: data2"),
            (
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "Invalid Bitcoin address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            ),
        ] {
            let (_, e) = d(json!([[{"txid": txid, "vout": 0}], [{key: 0.01}]]));
            assert_eq!(e.unwrap(), (RPC_INVALID_ADDRESS_OR_KEY, expect.to_string()));
        }
        let (_, e) = d(json!([[{"txid": txid, "vout": 0}], [{addr: 0.01}, {addr: 0.02}]]));
        assert_eq!(
            e.unwrap(),
            (
                RPC_INVALID_PARAMETER,
                format!("Invalid parameter, duplicated address: {addr}")
            )
        );

        // Locktime — i64 parse then the u32 bound; explicit-replaceable
        // with a final sequence is the combination error.
        for (lt, expect) in [
            (json!(-1), "Invalid parameter, locktime out of range"),
            (
                json!(4_294_967_296u64),
                "Invalid parameter, locktime out of range",
            ),
        ] {
            let (_, e) = d(json!([[{"txid": txid, "vout": 0}], [{"data": "aa"}], lt]));
            assert_eq!(e.unwrap(), (RPC_INVALID_PARAMETER, expect.to_string()));
        }
        let (_, e) = d(json!([[{"txid": txid, "vout": 0}], [{"data": "aa"}], 1.5]));
        assert_eq!(
            e.unwrap(),
            (RPC_MISC_ERROR, "JSON integer out of range".to_string())
        );
        for seq in [json!(u32::MAX), json!(u32::MAX - 1)] {
            let (_, e) = d(json!([
                [{"txid": txid, "vout": 0, "sequence": seq}],
                [{"data": "aa"}],
                0,
                true
            ]));
            assert_eq!(
                e.unwrap(),
                (
                    RPC_INVALID_PARAMETER,
                    "Invalid parameter combination: Sequence number(s) contradict replaceable \
                     option"
                        .to_string()
                )
            );
        }

        // Valid shapes — the data-only empty-input transaction is the
        // literal Core produced on regtest.
        let (r, e) = d(json!([[], [{"data": "aa"}]]));
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, "0200000000010000000000000000036a01aa00000000");
        // replaceable defaults to true → BIP125 sequence.
        let (r, e) = d(json!([[{"txid": txid, "vout": 0}], [{"data": "aa"}]]));
        assert!(e.is_none(), "{e:?}");
        assert_eq!(
            r,
            format!("0200000001{txid}0000000000fdffffff010000000000000000036a01aa00000000")
        );
        // locktime without replaceable → SEQUENCE_FINAL - 1.
        let (r, e) = d(json!([[{"txid": txid, "vout": 0}], [{"data": "aa"}], 5, false]));
        assert!(e.is_none(), "{e:?}");
        assert_eq!(
            r,
            format!("0200000001{txid}0000000000feffffff010000000000000000036a01aa05000000")
        );
        // Address + string amount; dict form preserves key order.
        let (r, e) = d(json!([[{"txid": txid, "vout": 0}], {addr: "0.01"}, 0, false]));
        assert!(e.is_none(), "{e:?}");
        assert_eq!(
            r,
            format!(
                "0200000001{txid}0000000000ffffffff0140420f0000000000160014ad7d5448cc0401eb51b0666484f2e7e3c1f9800700000000"
            )
        );
    }

    /// `createmultisig` — Core's `AddAndGetMultisigDestination`
    /// contract: keys parse before the address type, bounds in order
    /// (required ≥ 1, enough keys, ≤ 20, ≤ 520-byte script), and
    /// uncompressed keys drop segwit types to legacy with a warning.
    #[test]
    fn createmultisig_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let d = |p: Value| dispatch("createmultisig", &p, &snap, Some(&queries), None, None);
        let k1 = "035b29c4f18c17f8f1142ca109c0590a3872f91a32be254a045a31481581f098d6";
        let k2 = "02cbef9c21d191602794a1f7cf07ade94ba8d435ae017e1fa841ba6a20ae5208bc";
        let uncompr = "04989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f\
                       631f4d05b3ae518776ee08755a7703e64b2ebc32547504de0b55a142d4ecdf80";
        let uncompr = uncompr.replace(' ', "");
        let redeem = format!("5221{k1}21{k2}52ae");

        // Arity — two required args, at most three.
        for p in [json!([]), json!([2]), json!([2, [k1, k2], "legacy", 0])] {
            let (code, msg) = d(p.clone()).1.unwrap();
            assert_eq!(code, RPC_MISC_ERROR, "{p}");
            assert!(msg.starts_with("createmultisig"), "{msg}");
        }

        // Collected -3 list: all three positions report together.
        let (code, msg) = d(json!(["x", 1, 2])).1.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (nrequired)"), "{msg}");
        assert!(msg.contains("Position 2 (keys)"), "{msg}");
        assert!(msg.contains("Position 3 (address_type)"), "{msg}");

        // Non-integral / out-of-i32 nrequired.
        for n in [json!(1.5), json!("1"), json!(4294967296u64)] {
            // "1" string triggers the collected -3, not the -1 range.
            let (code, msg) = d(json!([n, [k1]])).1.unwrap();
            if code == RPC_MISC_ERROR {
                assert_eq!(msg, "JSON integer out of range", "{msg}");
            } else {
                assert_eq!(code, RPC_TYPE_ERROR, "{msg}");
            }
        }

        // Keys elements: non-string → bare -3; bad hex and bad point →
        // -5 with the pubkey echoed.
        assert_eq!(
            d(json!([1, [7]])).1.unwrap(),
            (
                RPC_TYPE_ERROR,
                "JSON value of type number is not of expected type string".to_string()
            )
        );
        assert_eq!(
            d(json!([1, ["xx"]])).1.unwrap(),
            (
                RPC_INVALID_ADDRESS_OR_KEY,
                "Pubkey \"xx\" must be a hex string".to_string()
            )
        );
        let bad = "04".repeat(33); // wrong length → invalid point
        assert_eq!(
            d(json!([1, [bad]])).1.unwrap().0,
            RPC_INVALID_ADDRESS_OR_KEY
        );
        assert!(
            d(json!([1, [bad]]))
                .1
                .unwrap()
                .1
                .contains("cryptographically valid")
        );

        // AddAndGetMultisigDestination bounds, in Core's check order.
        assert_eq!(
            d(json!([0, [k1]])).1.unwrap(),
            (
                RPC_INVALID_PARAMETER,
                "a multisignature address must require at least one key to redeem".to_string()
            )
        );
        assert_eq!(
            d(json!([3, [k1, k2]])).1.unwrap(),
            (
                RPC_INVALID_PARAMETER,
                "not enough keys supplied (got 2 keys, but need at least 3 to redeem)".to_string()
            )
        );
        // >20 keys beats the not-enough-keys check.
        let (code, msg) = d(json!([2, vec![k1; 21]])).1.unwrap();
        assert_eq!(code, RPC_INVALID_PARAMETER);
        assert!(
            msg.starts_with("Number of keys involved in the multisignature address creation > 20"),
            "{msg}"
        );
        // 520-byte cap: 15 uncompressed keys = 1+15*66+2 = 693 > 520.
        let (code, msg) = d(json!([15, vec![uncompr.as_str(); 15]])).1.unwrap();
        assert_eq!(code, RPC_INVALID_PARAMETER);
        assert!(msg.starts_with("redeemScript exceeds size limit:"), "{msg}");

        // Address types — exact Core 29.4 outputs for k1/k2.
        let cases: [(Option<&str>, &str, &str); 4] = [
            (None, "2N5mNBUAv6pMgxsoNcLf1y4TyoFYm4Mqu3Q", "sh"),
            (Some("legacy"), "2N5mNBUAv6pMgxsoNcLf1y4TyoFYm4Mqu3Q", "sh"),
            (
                Some("p2sh-segwit"),
                "2NFJNKEsV9Jcveaz8Mx7Bgxqkwcennt3s1E",
                "sh(wsh",
            ),
            (
                Some("bech32"),
                "bcrt1qzeyrz7mnwfkxnk9f9fh79x8zdddvwlc3uetchjv9k2ypa4syr4ks2zry75",
                "wsh",
            ),
        ];
        for (at, addr, desc_prefix) in cases {
            let mut p = json!([2, [k1, k2]]);
            if let Some(at) = at {
                p.as_array_mut().unwrap().push(json!(at));
            }
            let (r, e) = d(p);
            assert!(e.is_none(), "{e:?}");
            assert_eq!(r["address"], addr);
            assert_eq!(r["redeemScript"], redeem);
            let desc = r["descriptor"].as_str().unwrap();
            assert!(desc.starts_with(desc_prefix), "{desc}");
            assert!(desc.contains(&format!("multi(2,{k1},{k2})")), "{desc}");
            assert!(r["warnings"].is_null(), "no warnings for {at:?}");
        }
        // The descriptor checksum is Core's own algorithm.
        let (r, _) = d(json!([2, [k1, k2]]));
        assert_eq!(
            r["descriptor"],
            "sh(multi(2,035b29c4f18c17f8f1142ca109c0590a3872f91a32be254a045a31481581f098d6,02cbef9c21d191602794a1f7cf07ade94ba8d435ae017e1fa841ba6a20ae5208bc))#r47h6hf6"
        );

        // bech32m is named-but-refused; unknown types -5.
        assert_eq!(
            d(json!([2, [k1, k2], "bech32m"])).1.unwrap(),
            (
                RPC_INVALID_ADDRESS_OR_KEY,
                "createmultisig cannot create bech32m multisig addresses".to_string()
            )
        );
        assert_eq!(
            d(json!([2, [k1, k2], "bogus"])).1.unwrap(),
            (
                RPC_INVALID_ADDRESS_OR_KEY,
                "Unknown address type 'bogus'".to_string()
            )
        );

        // Uncompressed keys silently drop segwit to legacy + warn;
        // legacy itself stays silent.
        let (r, e) = d(json!([2, [k1, uncompr.as_str()], "bech32"]));
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["address"], "2N2WdGWrh4Vd74Z3QyYU6Wm2euJmzE2nrpm");
        assert_eq!(
            r["warnings"],
            json!([
                "Unable to make chosen address type, please ensure no uncompressed public keys are present."
            ])
        );
        assert!(
            r["descriptor"].as_str().unwrap().starts_with("sh(multi("),
            "{}",
            r["descriptor"]
        );
        let (r, _) = d(json!([2, [k1, uncompr.as_str()], "legacy"]));
        assert!(r["warnings"].is_null(), "no warning for plain legacy");

        // Empty key list hits the required-count checks, not a crash.
        assert_eq!(d(json!([1, []])).1.unwrap().0, RPC_INVALID_PARAMETER);
    }

    /// `verifymessage`/`signmessagewithprivkey` — Core's compact-sig
    /// pair: `verifymessage` walks decode → PKHash → base64 → recover,
    /// and `signmessagewithprivkey` emits Core's exact base64 for a
    /// WIF+message.
    #[test]
    fn message_signing_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let d = |method: &str, p: Value| dispatch(method, &p, &snap, Some(&queries), None, None);
        // Secret 0x07…07 — Core 29.4 outputs captured live.
        let wif_c = "cMpMxK92W1DjqDvWV3pMn4xLwAuQJhNF3MFqkEHUQRPQofUJku8R";
        let wif_u = "91e1fpA4xxnUq5jwFxvKkk37nMNPVw1HKf7zGES2gHrV3uSs7pU";
        let addr_c = "mvSvTtvD9H9fkgi8MGDyLALgRaR2LhnWFM"; // compressed pubkey p2pkh
        let addr_u = "mtag3YhK77meX1xqYrvdRhFPZdgNmt9Bdu"; // uncompressed p2pkh
        let sig_c = "IC93+OZbt0MJurMvm3NHxjW3mBdHGcrY6IlCuw2LiX9kerUXaMAMXxlM4vv6mBtD/G81gwpyitAQp53tC0GMXx8=";
        let sig_u = "HC93+OZbt0MJurMvm3NHxjW3mBdHGcrY6IlCuw2LiX9kerUXaMAMXxlM4vv6mBtD/G81gwpyitAQp53tC0GMXx8=";

        // signmessagewithprivkey — arity and collected types.
        for p in [json!([]), json!([wif_c]), json!([wif_c, "m", "x"])] {
            let (code, msg) = d("signmessagewithprivkey", p).1.unwrap();
            assert_eq!(code, RPC_MISC_ERROR);
            assert!(msg.starts_with("signmessagewithprivkey"), "{msg}");
        }
        let (code, msg) = d("signmessagewithprivkey", json!([1, 2])).1.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (privkey)"), "{msg}");
        assert!(msg.contains("Position 2 (message)"), "{msg}");
        assert_eq!(
            d("signmessagewithprivkey", json!(["bogus", "hi"]))
                .1
                .unwrap(),
            (
                RPC_INVALID_ADDRESS_OR_KEY,
                "Invalid private key".to_string()
            )
        );
        // Byte-identical signatures to Core for both key forms.
        assert_eq!(
            d("signmessagewithprivkey", json!([wif_c, "hi"])).0,
            json!(sig_c)
        );
        assert_eq!(
            d("signmessagewithprivkey", json!([wif_u, "hi"])).0,
            json!(sig_u)
        );
        // Wrong-network WIF is an invalid private key.
        assert_eq!(
            d(
                "signmessagewithprivkey",
                json!(["KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", "hi"])
            )
            .1
            .unwrap()
            .0,
            RPC_INVALID_ADDRESS_OR_KEY
        );

        // verifymessage — arity and the 3-position collected list.
        for p in [
            json!([]),
            json!([addr_c]),
            json!([addr_c, sig_c]),
            json!([addr_c, sig_c, "m", "x"]),
        ] {
            let (code, msg) = d("verifymessage", p).1.unwrap();
            assert_eq!(code, RPC_MISC_ERROR);
            assert!(msg.starts_with("verifymessage"), "{msg}");
        }
        let (code, msg) = d("verifymessage", json!([1, 2, 3])).1.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        for pos in [
            "Position 1 (address)",
            "Position 2 (signature)",
            "Position 3 (message)",
        ] {
            assert!(msg.contains(pos), "{pos}: {msg}");
        }
        // Decode order: bad address → -5, non-PKHash → -3, bad b64 →
        // -3, then verify-only → bool.
        assert_eq!(
            d("verifymessage", json!(["bogus", sig_c, "hi"])).1.unwrap(),
            (RPC_INVALID_ADDRESS_OR_KEY, "Invalid address".to_string())
        );
        for addr in [
            "2N5mNBUAv6pMgxsoNcLf1y4TyoFYm4Mqu3Q",          // p2sh
            "bcrt1q60mkz939j6a95lw70x0a8hnq4urve6xw8j63jv", // bech32
        ] {
            assert_eq!(
                d("verifymessage", json!([addr, sig_c, "hi"])).1.unwrap(),
                (RPC_TYPE_ERROR, "Address does not refer to key".to_string())
            );
        }
        assert_eq!(
            d("verifymessage", json!([addr_c, "!!!", "hi"])).1.unwrap(),
            (RPC_TYPE_ERROR, "Malformed base64 encoding".to_string())
        );
        assert_eq!(
            d("verifymessage", json!([addr_c, "A A A", "hi"]))
                .1
                .unwrap(),
            (RPC_TYPE_ERROR, "Malformed base64 encoding".to_string())
        );
        // Wrong-length-but-valid b64, wrong message, wrong address,
        // wrong encoding form — all `false`.
        assert_eq!(
            d("verifymessage", json!([addr_c, "AAAA", "hi"])).0,
            json!(false)
        );
        assert_eq!(
            d("verifymessage", json!([addr_c, "", "hi"])).0,
            json!(false)
        );
        assert_eq!(
            d("verifymessage", json!([addr_c, sig_c, "bye"])).0,
            json!(false)
        );
        assert_eq!(
            d("verifymessage", json!([addr_u, sig_c, "hi"])).0,
            json!(false)
        );
        assert_eq!(
            d("verifymessage", json!([addr_c, sig_u, "hi"])).0,
            json!(false)
        );
        // Genuine verifications — each sig against its own address.
        assert_eq!(
            d("verifymessage", json!([addr_c, sig_c, "hi"])).0,
            json!(true)
        );
        assert_eq!(
            d("verifymessage", json!([addr_u, sig_u, "hi"])).0,
            json!(true)
        );
    }

    /// `getprioritisedtransactions` — the mapDeltas dump: txid-keyed in
    /// raw-byte order, `in_mempool`/`modified_fee` only for pooled txs.
    #[test]
    fn getprioritisedtransactions_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        let d = |m, p: Value| dispatch(m, &p, &snap, Some(&queries), None, None);

        // Any argument is a -1 + help, whatever its type.
        for p in [json!([1]), json!(["x"]), json!([true])] {
            let (code, msg) = d("getprioritisedtransactions", p).1.unwrap();
            assert_eq!(code, RPC_MISC_ERROR);
            assert!(msg.starts_with("getprioritisedtransactions"), "{msg}");
        }

        // Empty pool → empty object.
        let (r, e) = d("getprioritisedtransactions", json!([]));
        assert!(e.is_none());
        assert_eq!(r, json!({}));

        // Seed two deltas via prioritisetransaction — unknown txids
        // land in mapDeltas with in_mempool=false and no modified_fee.
        d("prioritisetransaction", json!(["cd".repeat(32), 0, 70_000]));
        d("prioritisetransaction", json!(["ab".repeat(32), 0, -5_000]));
        let (r, e) = d("getprioritisedtransactions", json!([]));
        assert!(e.is_none());
        // Raw-byte order: "ab"*32's bytes are 0xabab..; "cd"*32's are
        // 0xcdcd.. — display order and internal order agree for
        // palindromic hex, so also check the non-palindromic pair.
        assert_eq!(
            r["abababababababababababababababababababababababababababababababab"],
            json!({"fee_delta": -5_000, "in_mempool": false})
        );
        assert_eq!(
            r["cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"],
            json!({"fee_delta": 70_000, "in_mempool": false})
        );
        assert_eq!(r.as_object().unwrap().len(), 2);
        // Non-palindromic txids: internal byte order is the *reverse*
        // of display order — "00..ff" displays with ff at the end but
        // its raw bytes start 0xff, sorting after "ff..00" whose raw
        // bytes start 0x00.
        d(
            "prioritisetransaction",
            json!([format!("00{}ff", "11".repeat(30)), 0, 1]),
        );
        d(
            "prioritisetransaction",
            json!([format!("ff{}00", "22".repeat(30)), 0, 2]),
        );
        let (r, _) = d("getprioritisedtransactions", json!([]));
        let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
        let first_new = keys.iter().position(|k| k.starts_with("ff22")).unwrap();
        let second_new = keys.iter().position(|k| k.starts_with("0011")).unwrap();
        assert!(first_new < second_new, "{keys:?}");
    }

    /// `g16` — Core's `setFloat` text: `%.16g` with its fixed/scientific
    /// switch and trailing-zero strip. The 101/17 case is the observed
    /// last-digit divergence from ryu's shortest repr.
    #[test]
    fn g16_matches_univalue_setfloat() {
        assert_eq!(g16(101.0 / 17.0), "5.941176470588236");
        assert_eq!(g16(0.0), "0");
        assert_eq!(g16(-0.0), "-0");
        assert_eq!(g16(1.5), "1.5");
        assert_eq!(g16(100.0), "100");
        assert_eq!(g16(-42.25), "-42.25");
        // Exponent boundary: -4 ≤ exp < 16 stays fixed.
        assert_eq!(g16(0.0001), "0.0001");
        assert_eq!(g16(0.00001), "1e-05");
        assert_eq!(g16(1e15), "1000000000000000");
        assert_eq!(g16(1e16), "1e+16");
        assert_eq!(g16(2.5e20), "2.5e+20");
        assert_eq!(g16(-1.5e-5), "-1.5e-05");
    }

    /// `BlockWaiters` — `notify` fires satisfied predicates, `shutdown`
    /// wakes everything, and the registry stays bounded.
    #[test]
    fn block_waiters_notify_and_shutdown() {
        let cs = Chainstate::new(&Network::Regtest.params());
        let waiters = BlockWaiters::new();

        // A false predicate stays parked; a true one fires.
        let (tx, rx) = mpsc::sync_channel(1);
        assert!(waiters.register(Box::new(|_| false), tx));
        waiters.notify(&cs);
        assert!(rx.try_recv().is_err());
        let (tx, rx) = mpsc::sync_channel(1);
        assert!(waiters.register(Box::new(|_| true), tx));
        waiters.notify(&cs);
        assert!(rx.try_recv().is_ok());

        // The un-fired waiter and a fresh one both wake on shutdown.
        let (tx, rx) = mpsc::sync_channel(1);
        assert!(waiters.register(Box::new(|_| false), tx));
        waiters.shutdown();
        assert!(rx.try_recv().is_ok());
        assert!(!waiters.register(Box::new(|_| true), mpsc::sync_channel(1).0));
    }

    /// `getchaintxstats` — on the genesis-only fixture every window
    /// is out of range (Core's `height - 1` bound is -1 there), which
    /// still exercises the full validation order.
    #[test]
    fn getchaintxstats_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        // Arity → -1 + help.
        let (_, e) = dispatch(
            "getchaintxstats",
            &json!([1, "00", 3]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_MISC_ERROR);
        assert!(msg.starts_with("getchaintxstats"), "{msg}");

        // Both positions wrong-typed → the collected two-line -3 list.
        let (_, e) = dispatch(
            "getchaintxstats",
            &json!(["x", 1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (nblocks)"), "{msg}");
        assert!(msg.contains("Position 2 (blockhash)"), "{msg}");

        // Hash format precedes the count parse: bad length → -8.
        let (_, e) = dispatch(
            "getchaintxstats",
            &json!([1.5, "00"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);

        // An unknown well-formed hash precedes the count parse too.
        let unknown = "00".repeat(32);
        let (_, e) = dispatch(
            "getchaintxstats",
            &json!([1.5, unknown]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_INVALID_ADDRESS_OR_KEY, "Block not found".to_string())
        );

        // Non-integral nblocks on a known block → -1.
        let (_, e) = dispatch(
            "getchaintxstats",
            &json!([1.5]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(
            e.unwrap(),
            (RPC_MISC_ERROR, "JSON integer out of range".to_string())
        );

        // Genesis allows only the zero window — it answers with just
        // the final-block fields plus txcount, like Core at h0.
        for p in [json!([]), json!([0]), json!([null, null])] {
            let (r, e) = dispatch("getchaintxstats", &p, &snap, Some(&queries), None, None);
            assert!(e.is_none(), "{p}: {e:?}");
            assert_eq!(r["window_block_count"], json!(0), "{p}");
            assert_eq!(r["txcount"], json!(1), "{p}");
            assert!(r.get("window_interval").is_none(), "{p}");
            assert!(r.get("txrate").is_none(), "{p}");
        }
        // A nonzero window on genesis and negative counts → -8.
        for p in [json!([1]), json!([-1])] {
            let (_, e) = dispatch("getchaintxstats", &p, &snap, Some(&queries), None, None);
            let (code, msg) = e.unwrap();
            assert_eq!(code, RPC_INVALID_PARAMETER, "{p}");
            assert!(msg.contains("block's height - 1"), "{msg}");
        }
    }

    /// `gettxoutsetinfo` — hash-type selection, the collected type list,
    /// the coinstatsindex gate on `hash_or_height`, and the genesis-only
    /// (empty UTXO set) result shape.
    #[test]
    fn gettxoutsetinfo_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        // Arity → -1 + help.
        let (_, e) = dispatch(
            "gettxoutsetinfo",
            &json!(["none", null, true, 4]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_MISC_ERROR);
        assert!(msg.starts_with("gettxoutsetinfo"), "{msg}");

        // Wrong types collected across positions — hash_or_height
        // (position 2) is skip_type_check, so a number there is fine.
        let (_, e) = dispatch(
            "gettxoutsetinfo",
            &json!([7, null, "x"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (code, msg) = e.unwrap();
        assert_eq!(code, RPC_TYPE_ERROR);
        assert!(msg.contains("Position 1 (hash_type)"), "{msg}");
        assert!(msg.contains("Position 3 (use_index)"), "{msg}");
        assert!(!msg.contains("hash_or_height"), "{msg}");

        // An invalid hash_type is -8 before the index gate.
        let (_, e) = dispatch(
            "gettxoutsetinfo",
            &json!(["bogus"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        let (_, msg) = e.unwrap();
        assert_eq!(msg, "'bogus' is not a valid hash_type");

        // Any non-null target without coinstatsindex → -8, whatever
        // use_index says.
        for p in [
            json!(["none", 0]),
            json!(["muhash", "00".repeat(32), false]),
        ] {
            let (_, e) = dispatch("gettxoutsetinfo", &p, &snap, Some(&queries), None, None);
            assert_eq!(
                e.unwrap(),
                (
                    RPC_INVALID_PARAMETER,
                    "Querying specific block heights requires coinstatsindex".to_string()
                ),
                "{p}"
            );
        }

        // The empty genesis set: each hash type flips which key appears.
        for (p, key) in [
            (json!([]), "hash_serialized_3"),
            (json!(["muhash"]), "muhash"),
            (json!([null, null, false]), "hash_serialized_3"),
        ] {
            let (r, e) = dispatch("gettxoutsetinfo", &p, &snap, Some(&queries), None, None);
            assert!(e.is_none(), "{p}: {e:?}");
            assert_eq!(r["height"], json!(0), "{p}");
            assert_eq!(r["txouts"], json!(0), "{p}");
            assert_eq!(r["transactions"], json!(0), "{p}");
            assert_eq!(r["total_amount"], json!(0.0), "{p}");
            assert!(r.get(key).is_some(), "{p}");
        }
        let (r, e) = dispatch(
            "gettxoutsetinfo",
            &json!(["none"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert!(r.get("hash_serialized_3").is_none());
        assert!(r.get("muhash").is_none());
    }

    /// `getrpcinfo`/`getmemoryinfo`/`logging` — the introspection
    /// surface: shapes, mode/category errors, and type contract.
    #[test]
    fn introspection_dispatch_contract() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();

        // getrpcinfo: the in-flight command names itself; logpath is
        // empty without a store. Any arg → -1 + help.
        let (r, e) = dispatch("getrpcinfo", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["active_commands"][0]["method"], json!("getrpcinfo"));
        assert!(r["active_commands"][0]["duration"].is_u64());
        assert_eq!(r["logpath"], json!(""));
        let (_, e) = dispatch("getrpcinfo", &json!([1]), &snap, Some(&queries), None, None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);

        // getmemoryinfo: stats shape; unknown mode → -8; bad type → -3.
        let (r, e) = dispatch(
            "getmemoryinfo",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["locked"]["total"], json!(0));
        let (_, e) = dispatch(
            "getmemoryinfo",
            &json!(["bogus"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getmemoryinfo",
            &json!([5]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);

        // logging: 28 categories all-false at rest; include/exclude in
        // order; "all"/"1" specials; unknown → -8; bad types → -3.
        let (r, e) = dispatch("logging", &json!([]), &snap, Some(&queries), None, None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r.as_object().unwrap().len(), 28);
        assert!(r.as_object().unwrap().values().all(|v| *v == json!(false)));
        let (r, _) = dispatch(
            "logging",
            &json!([["net", "mempool"]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r["net"], json!(true));
        assert_eq!(r["mempool"], json!(true));
        let (r, _) = dispatch(
            "logging",
            &json!([[], ["net"]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r["net"], json!(false));
        assert_eq!(r["mempool"], json!(true));
        let (r, _) = dispatch(
            "logging",
            &json!([["mempool"], ["mempool"]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r["mempool"], json!(false));
        let (_, e) = dispatch(
            "logging",
            &json!([["boguscat"]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch("logging", &json!([5]), &snap, Some(&queries), None, None);
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);
        // Reset so other tests see a clean map.
        let _ = dispatch(
            "logging",
            &json!([[], ["all"]]),
            &snap,
            Some(&queries),
            None,
            None,
        );
    }

    /// `getnodeaddresses` — Core's count/network argument contract and
    /// `{time, services, address, port, network}` entry shape.
    #[test]
    fn getnodeaddresses_reports_book_entries() {
        let queries = query_server(Chainstate::new(&Network::Regtest.params()));
        let snap = snap();
        // Seed the book through the test-only injection RPC.
        let (r, e) = dispatch(
            "addpeeraddress",
            &json!(["93.184.216.34", 18444]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!({"success": true}));
        // Unroutable and duplicate adds fail like Core's AddSingle.
        let (r, e) = dispatch(
            "addpeeraddress",
            &json!(["127.0.0.1", 8333]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(
            r,
            json!({"error": "failed-adding-to-new", "success": false})
        );
        let (r, _) = dispatch(
            "addpeeraddress",
            &json!(["93.184.216.34", 18444]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r["success"], json!(false));
        // Unparseable → success:false with no error key.
        let (r, _) = dispatch(
            "addpeeraddress",
            &json!(["notanip", 8333]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r, json!({"success": false}));

        let (r, e) = dispatch(
            "getnodeaddresses",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert!(e.is_none(), "{e:?}");
        let entries = r.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["address"], json!("93.184.216.34"));
        assert_eq!(entries[0]["port"], json!(18444));
        assert_eq!(entries[0]["network"], json!("ipv4"));
        assert_eq!(entries[0]["services"], json!(9)); // NODE_NETWORK|NODE_WITNESS
        // Filtered views: matching name returns, non-matching empties.
        let (r, _) = dispatch(
            "getnodeaddresses",
            &json!([0, "ipv4"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r.as_array().unwrap().len(), 1);
        let (r, _) = dispatch(
            "getnodeaddresses",
            &json!([0, "onion"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(r.as_array().unwrap().len(), 0);
        // Error paths.
        let (_, e) = dispatch(
            "getnodeaddresses",
            &json!([-1]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getnodeaddresses",
            &json!([5, "bogus"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getnodeaddresses",
            &json!(["x"]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);
        let (_, e) = dispatch(
            "addpeeraddress",
            &json!([]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch(
            "addpeeraddress",
            &json!(["1.2.3.4", 70000]),
            &snap,
            Some(&queries),
            None,
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }
}

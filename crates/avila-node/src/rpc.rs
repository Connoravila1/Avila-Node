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
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::Duration;

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
                    let stop = stop.clone();
                    let auth = auth.clone();
                    thread::spawn(move || {
                        handle(
                            stream,
                            &status,
                            queries.as_ref(),
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

/// Core's `DEFAULT_MAX_RAW_TX_FEE_RATE` — `sendrawtransaction` refuses
/// txs paying more than this unless the caller raises it (BTC/kvB).
const DEFAULT_MAX_RAW_TX_FEE_RATE: f64 = 0.10;

fn handle(
    mut stream: TcpStream,
    status: &SharedStatus,
    queries: Option<&QuerySender>,
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
    let (result, error) = dispatch(method, &params, &snap, queries, stop);
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

/// `RPCTypeCheckArgument`'s message — the `Wrong type passed:` list
/// keyed by position and argument name.
fn wrong_type_message(position: usize, name: &str, v: &Value, expected: &str) -> String {
    format!(
        "Wrong type passed:\n{{\n    \"Position {position} ({name})\": \
         \"JSON value of type {} is not of expected type {expected}\"\n}}",
        json_type_name(v)
    )
}

/// The bare field/element type error — `RPCTypeCheckObj`/`RPCTypeCheck`
/// wording without the `Position` wrapper Core adds at top level.
fn field_type_message(v: &Value, expected: &str) -> String {
    format!(
        "JSON value of type {} is not of expected type {expected}",
        json_type_name(v)
    )
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

/// Core throws the method's full `RPCHelpMan` text as a -1 error when
/// required args are absent or the arg count is out of range.
fn help_error(text: &'static str) -> (Value, Option<(i64, String)>) {
    (Value::Null, Some((RPC_MISC_ERROR, text.to_string())))
}

/// Verbatim `help decoderawtransaction` text (Bitcoin Core 29).
const DECODERAWTRANSACTION_HELP: &str = "decoderawtransaction \"hexstring\" ( iswitness )\n\nReturn a JSON object representing the serialized, hex-encoded transaction.\n\nArguments:\n1. hexstring    (string, required) The transaction hex string\n2. iswitness    (boolean, optional, default=depends on heuristic tests) Whether the transaction hex is a serialized witness transaction.\n                If iswitness is not present, heuristic tests will be used in decoding.\n                If true, only witness deserialization will be tried.\n                If false, only non-witness deserialization will be tried.\n                This boolean should reflect whether the transaction has inputs\n                (e.g. fully valid, or on-chain transactions), if known by the caller.\n\nResult:\n{                             (json object)\n  \"txid\" : \"hex\",             (string) The transaction id\n  \"hash\" : \"hex\",             (string) The transaction hash (differs from txid for witness transactions)\n  \"size\" : n,                 (numeric) The serialized transaction size\n  \"vsize\" : n,                (numeric) The virtual transaction size (differs from size for witness transactions)\n  \"weight\" : n,               (numeric) The transaction's weight (between vsize*4-3 and vsize*4)\n  \"version\" : n,              (numeric) The version\n  \"locktime\" : xxx,           (numeric) The lock time\n  \"vin\" : [                   (json array)\n    {                         (json object)\n      \"coinbase\" : \"hex\",     (string, optional) The coinbase value (only if coinbase transaction)\n      \"txid\" : \"hex\",         (string, optional) The transaction id (if not coinbase transaction)\n      \"vout\" : n,             (numeric, optional) The output number (if not coinbase transaction)\n      \"scriptSig\" : {         (json object, optional) The script (if not coinbase transaction)\n        \"asm\" : \"str\",        (string) Disassembly of the signature script\n        \"hex\" : \"hex\"         (string) The raw signature script bytes, hex-encoded\n      },\n      \"txinwitness\" : [       (json array, optional)\n        \"hex\",                (string) hex-encoded witness data (if any)\n        ...\n      ],\n      \"sequence\" : n          (numeric) The script sequence number\n    },\n    ...\n  ],\n  \"vout\" : [                  (json array)\n    {                         (json object)\n      \"value\" : n,            (numeric) The value in BTC\n      \"n\" : n,                (numeric) index\n      \"scriptPubKey\" : {      (json object)\n        \"asm\" : \"str\",        (string) Disassembly of the output script\n        \"desc\" : \"str\",       (string) Inferred descriptor for the output\n        \"hex\" : \"hex\",        (string) The raw output script bytes, hex-encoded\n        \"address\" : \"str\",    (string, optional) The Bitcoin address (only if a well-defined address exists)\n        \"type\" : \"str\"        (string) The type (one of: nonstandard, anchor, pubkey, pubkeyhash, scripthash, multisig, nulldata, witness_v0_scripthash, witness_v0_keyhash, witness_v1_taproot, witness_unknown)\n      }\n    },\n    ...\n  ]\n}\n\nExamples:\n> bitcoin-cli decoderawtransaction \"hexstring\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"decoderawtransaction\", \"params\": [\"hexstring\"]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help gettxspendingprevout` text (Bitcoin Core 29).
const GETTXSPENDINGPREVOUT_HELP: &str = "gettxspendingprevout [{\"txid\":\"hex\",\"vout\":n},...]\n\nScans the mempool to find transactions spending any of the given outputs\n\nArguments:\n1. outputs                 (json array, required) The transaction outputs that we want to check, and within each, the txid (string) vout (numeric).\n     [\n       {                   (json object)\n         \"txid\": \"hex\",    (string, required) The transaction id\n         \"vout\": n,        (numeric, required) The output number\n       },\n       ...\n     ]\n\nResult:\n[                              (json array)\n  {                            (json object)\n    \"txid\" : \"hex\",            (string) the transaction id of the checked output\n    \"vout\" : n,                (numeric) the vout value of the checked output\n    \"spendingtxid\" : \"hex\"     (string, optional) the transaction id of the mempool transaction spending this output (omitted if unspent)\n  },\n  ...\n]\n\nExamples:\n> bitcoin-cli gettxspendingprevout \"[{\\\"txid\\\":\\\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\\\",\\\"vout\\\":3}]\"\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"gettxspendingprevout\", \"params\": [[{\"txid\":\"a08e6907dbbd3d809776dbfc5d82e371b764ed838b5655e72f463568df1aadf0\",\"vout\":3}]]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help estimatesmartfee` text (Bitcoin Core 29).
const ESTIMATESMARTFEE_HELP: &str = "estimatesmartfee conf_target ( \"estimate_mode\" )\n\nEstimates the approximate fee per kilobyte needed for a transaction to begin\nconfirmation within conf_target blocks if possible and return the number of blocks\nfor which the estimate is valid. Uses virtual transaction size as defined\nin BIP 141 (witness data is discounted).\n\nArguments:\n1. conf_target      (numeric, required) Confirmation target in blocks (1 - 1008)\n2. estimate_mode    (string, optional, default=\"economical\") The fee estimate mode.\n                    unset, economical, conservative \n                    unset means no mode set (default mode will be used). \n                    economical estimates use a shorter time horizon, making them more\n                    responsive to short-term drops in the prevailing fee market. This mode\n                    potentially returns a lower fee rate estimate.\n                    conservative estimates use a longer time horizon, making them\n                    less responsive to short-term drops in the prevailing fee market. This mode\n                    potentially returns a higher fee rate estimate.\n                    \n\nResult:\n{                   (json object)\n  \"feerate\" : n,    (numeric, optional) estimate fee rate in BTC/kvB (only present if no errors were encountered)\n  \"errors\" : [      (json array, optional) Errors encountered during processing (if there are any)\n    \"str\",          (string) error\n    ...\n  ],\n  \"blocks\" : n      (numeric) block number where estimate was found\n                    The request target will be clamped between 2 and the highest target\n                    fee estimation is able to return based on how long it has been running.\n                    An error is returned if not enough transactions and blocks\n                    have been observed to make an estimate for any number of blocks.\n}\n\nExamples:\n> bitcoin-cli estimatesmartfee 6\n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"estimatesmartfee\", \"params\": [6]}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getnetworkhashps` text (Bitcoin Core 29).
const GETNETWORKHASHPS_HELP: &str = "getnetworkhashps ( nblocks height )\n\nReturns the estimated network hashes per second based on the last n blocks.\nPass in [blocks] to override # of blocks, -1 specifies since last difficulty change.\nPass in [height] to estimate the network speed at the time when a certain block was found.\n\nArguments:\n1. nblocks    (numeric, optional, default=120) The number of previous blocks to calculate estimate from, or -1 for blocks since last difficulty change.\n2. height     (numeric, optional, default=-1) To estimate at the time of the given height.\n\nResult:\nn    (numeric) Hashes per second estimated\n\nExamples:\n> bitcoin-cli getnetworkhashps \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getnetworkhashps\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getnettotals` text (Bitcoin Core 29).
const GETNETTOTALS_HELP: &str = "getnettotals\n\nReturns information about network traffic, including bytes in, bytes out,\nand current system time.\n\nResult:\n{                                              (json object)\n  \"totalbytesrecv\" : n,                        (numeric) Total bytes received\n  \"totalbytessent\" : n,                        (numeric) Total bytes sent\n  \"timemillis\" : xxx,                          (numeric) Current system UNIX epoch time in milliseconds\n  \"uploadtarget\" : {                           (json object)\n    \"timeframe\" : n,                           (numeric) Length of the measuring timeframe in seconds\n    \"target\" : n,                              (numeric) Target in bytes\n    \"target_reached\" : true|false,             (boolean) True if target is reached\n    \"serve_historical_blocks\" : true|false,    (boolean) True if serving historical blocks\n    \"bytes_left_in_cycle\" : n,                 (numeric) Bytes left in current time cycle\n    \"time_left_in_cycle\" : n                   (numeric) Seconds left in current time cycle\n  }\n}\n\nExamples:\n> bitcoin-cli getnettotals \n> curl --user myusername --data-binary '{\"jsonrpc\": \"2.0\", \"id\": \"curltest\", \"method\": \"getnettotals\", \"params\": []}' -H 'content-type: application/json' http://127.0.0.1:8332/\n";

/// Verbatim `help getnodeaddresses` text (Bitcoin Core 29).
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
                    "period_start": stats.period_start,
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
    let stat = |set: &std::collections::HashSet<Txid>| -> (usize, usize, i64) {
        let mut size = 0usize;
        let mut fees = 0i64;
        for id in set {
            if let Some(e) = pool.entry(id) {
                size += e.vsize;
                fees += e.fee;
            }
        }
        (set.len(), size, fees)
    };
    let (acount, asize, afees) = stat(&ancestors);
    let (dcount, dsize, dfees) = stat(&descendants);
    json!({
        "vsize": entry.vsize,
        "weight": entry.vsize * 4,
        "time": entry.time,
        "height": entry.first_seen_height,
        "wtxid": entry.tx.wtxid().to_string(),
        "fees": {
            "base": entry.fee as f64 / 100_000_000.0,
        },
        "ancestorcount": acount + 1,
        "ancestorsize": asize + entry.vsize,
        "ancestorfees": afees + entry.fee,
        "descendantcount": dcount + 1,
        "descendantsize": dsize + entry.vsize,
        "descendantfees": dfees + entry.fee,
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
    stop: Option<&Arc<AtomicBool>>,
) -> (Value, Option<(i64, String)>) {
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
                    Err((error, locations)) => {
                        let mut out = json!({
                            "isvalid": false,
                            "error_locations": locations,
                            "error": error,
                        });
                        // Core emits error_index = the first located
                        // position when any were found.
                        if let Some(first) = locations.first() {
                            out["error_index"] = json!(first);
                        }
                        Ok(out)
                    }
                }
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
                // No size-based decay yet — the dynamic floor equals
                // the configured relay floor until that lands.
                "mempoolminfee": relay_btc,
                "minrelaytxfee": relay_btc,
                "incrementalrelayfee": sat_to_btc(avila_mempool::INCREMENTAL_RELAY_FEE),
                // Our replacement rule is BIP125 opt-in signaling, not
                // Core's mempoolfullrbf — the honest answer is false.
                "fullrbf": false,
                "unbroadcastcount": 0,
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
                        // peer (Core's RelayTransaction path).
                        mgr.announce_tx(txid, wtxid);
                        Ok(json!(txid.to_string()))
                    }
                    Err(avila_mempool::MempoolReject::AlreadyKnown) => Ok(json!(txid.to_string())),
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
            // size/weight/tx count honestly.
            let current = mgr
                .mempool_ref()
                .build_template(cs, Script::new(vec![avila_consensus::script::OP_1]), now)
                .ok();
            // networkhashps — Core's GetNetworkHashPS(120, -1): the
            // default 120-block window at the tip.
            let networkhashps = network_hashps(cs, 120, -1);
            let mut out = json!({
                "blocks": node.height,
                "currentblocksize": current.as_ref().map(|t| t.block.encode().len()).unwrap_or(0),
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
                "networkactive": true,
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
                 \x20   verifytxoutproof <proof> [options], validateaddress <address>\n\
                 \x20 mempool: getmempoolinfo, getrawmempool [verbose], getmempoolentry <txid>,\n\
                 \x20   getmempoolancestors|getmempooldescendants <txid> [verbose],\n\
                 \x20   gettxspendingprevout <outputs>,\n\
                 \x20   getorphantxs, testmempoolaccept <rawtx | [rawtx,...]>,\n\
                 \x20   sendrawtransaction <hex> [maxfeerate] [maxburnamount], savemempool\n\
                 \x20 mining: getblocktemplate, getmininginfo, getnetworkhashps,\n\
                 \x20   submitblock <hex>,\n\
                 \x20   submitheader <hex>, generatetoaddress <n> <address> [maxtries],\n\
                 \x20   generateblock <output> [rawtx/txid,...]\n\
                 \x20 net:   getpeerinfo, getconnectioncount, getnetworkinfo,\n\
                 \x20   getnettotals, getnodeaddresses [count] [network],\n\
                 \x20   addpeeraddress <address> <port> [tried]\n\
                 \x20 misc:  estimatesmartfee <target>, uptime, help, stop"
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
        dispatch(method, params, snap, None, None)
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
        let (_, e) = dispatch("getblockhash", &json!([0]), &snap, None, None);
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
        let (r, e) = dispatch("stop", &Value::Null, &snap, None, Some(&flag));
        assert!(e.is_none());
        assert_eq!(r, json!("Avila node stopping"));
        assert!(flag.load(Ordering::Relaxed));
        // Without a run loop the call reports honestly instead of lying.
        let (_, e) = dispatch("stop", &Value::Null, &snap, None, None);
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

        let (r, e) = dispatch("getblockhash", &json!([0]), &snap, Some(&queries), None);
        assert!(e.is_none());
        let genesis = r.as_str().unwrap().to_string();

        let (r, e) = dispatch(
            "getblockheader",
            &json!([genesis]),
            &snap,
            Some(&queries),
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
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["hash"], genesis);
        assert_eq!(r["height"], 0);
        assert_eq!(r["tx"][0].as_str().unwrap().len(), 64);

        // Unknown heights/hashes get Core's error codes, not nulls.
        let (_, e) = dispatch("getblockhash", &json!([99]), &snap, Some(&queries), None);
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getblockheader",
            &json!([BlockHash::from_bytes([9u8; 32]).to_string()]),
            &snap,
            Some(&queries),
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
        );
        assert!(e.is_none());
        let (r, _) = dispatch(
            "gettxout",
            &json!([Txid::from_bytes([1u8; 32]).to_string(), 0]),
            &snap,
            Some(&queries),
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
        let (r, e) = dispatch("getmempoolinfo", &Value::Null, &snap, Some(&queries), None);
        assert!(e.is_none(), "{e:?}");
        for key in [
            "loaded",
            "size",
            "bytes",
            "usage",
            "total_fee",
            "mempoolminfee",
            "minrelaytxfee",
            "unbroadcastcount",
        ] {
            assert!(r.get(key).is_some(), "getmempoolinfo missing {key}");
        }

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
        let (r, e) = dispatch("getmininginfo", &Value::Null, &snap, Some(&queries), None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["chain"], "regtest");
        assert_eq!(r["next"]["height"], 1);
        assert!(r["next"]["target"].is_string());

        // An empty pool has no confirmation samples — Core returns a
        // result object with `errors`, not an RPC error.
        let (r, e) = dispatch("estimatesmartfee", &json!([6]), &snap, Some(&queries), None);
        assert!(e.is_none());
        assert_eq!(
            r,
            json!({"errors": ["Insufficient data or no feerate found"], "blocks": 0})
        );

        // getnetworkinfo splits in/out connections.
        let (r, e) = dispatch("getnetworkinfo", &Value::Null, &snap, Some(&queries), None);
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
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMS);
        let (_, e) = dispatch(
            "sendrawtransaction",
            &json!(["00", -1]),
            &snap,
            Some(&queries),
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
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        let (_, e) = dispatch(
            "sendrawtransaction",
            &json!(["00ff"]),
            &snap,
            Some(&queries),
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
        );
        let err = e.unwrap();
        assert_eq!(err.0, RPC_VERIFY_REJECTED);
        assert_eq!(err.1, "bad-cb-length");

        // Without the query channel the method reports honestly.
        let (_, e) = dispatch("sendrawtransaction", &json!(["00"]), &snap, None, None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }

    /// `savemempool` — without a block store there is nowhere to write;
    /// the method reports the misc error rather than fabricate a path.
    #[test]
    fn savemempool_reports_missing_store() {
        let cs = Chainstate::new(&Network::Regtest.params());
        let queries = query_server(cs);
        let snap = snap();
        let (_, e) = dispatch("savemempool", &Value::Null, &snap, Some(&queries), None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch("savemempool", &Value::Null, &snap, None, None);
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
        let (r, e) = dispatch("getblockstats", &json!([0]), &snap, Some(&queries), None);
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
        );
        assert!(e.is_none());
        assert_eq!(r["txs"], json!(1));
        assert!(r.get("avgfee").is_none(), "filtered key must be absent");

        // Out-of-range height and malformed hash carry Core's wording.
        let (_, e) = dispatch("getblockstats", &json!([99]), &snap, Some(&queries), None);
        assert_eq!(e.unwrap().1, "Target block height 99 after current tip 0");
        let (_, e) = dispatch(
            "getblockstats",
            &json!(["deadbeef"]),
            &snap,
            Some(&queries),
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
        let (r, e) = dispatch("getdeploymentinfo", &json!([]), &snap, Some(&queries), None);
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
        );
        assert!(e.is_none(), "{e:?}");
        let proof = r.as_str().unwrap().to_string();
        let (r, e) = dispatch(
            "verifytxoutproof",
            &json!([proof]),
            &snap,
            Some(&queries),
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

        let (_, e) = dispatch("gettxoutproof", &json!([]), &snap, Some(&queries), None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch("gettxoutproof", &json!([[]]), &snap, Some(&queries), None);
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
        );
        assert_eq!(
            e.unwrap(),
            (
                RPC_MISC_ERROR,
                "DataStream::read(): end of data: iostream error".into()
            )
        );
        // A proof whose header doesn't resolve on the active chain.
        let mut header = genesis.header.clone();
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
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null); // connected — Core's null
        let (r, e) = dispatch(
            "submitblock",
            &json!([hexdata]),
            &snap,
            Some(&queries),
            None,
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!("duplicate"));

        // Decode failures carry Core's -22.
        let (_, e) = dispatch("submitblock", &json!(["aabb"]), &snap, Some(&queries), None);
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        let (_, e) = dispatch("submitblock", &json!([]), &snap, Some(&queries), None);
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
        );
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, Value::Null);

        let (_, e) = dispatch("submitheader", &json!(["zz"]), &snap, Some(&queries), None);
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
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_ADDRESS_OR_KEY);

        // generateblock: coinbase-only block pays a descriptor.
        let (r, e) = dispatch(
            "generateblock",
            &json!([format!("addr({addr})"), []]),
            &snap,
            Some(&queries),
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
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        // Bad output → -5.
        let (_, e) = dispatch(
            "generateblock",
            &json!(["zzz", []]),
            &snap,
            Some(&queries),
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
            let (r, e) = dispatch("decoderawtransaction", &p, &snap, Some(&queries), None);
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
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        let (_, e) = dispatch(
            "decoderawtransaction",
            &json!(["00"]),
            &snap,
            Some(&queries),
            None,
        );
        assert_eq!(e.unwrap().0, RPC_DESERIALIZATION_ERROR);
        let (_, e) = dispatch(
            "decoderawtransaction",
            &json!([cb_hex, 2]),
            &snap,
            Some(&queries),
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
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch(
            "decoderawtransaction",
            &json!([cb_hex, true, 1]),
            &snap,
            Some(&queries),
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
        let (r, e) = dispatch("getindexinfo", &json!([]), &snap, Some(&queries), None);
        assert!(e.is_none());
        assert_eq!(r, json!({}));

        let mut cs = Chainstate::new(&Network::Regtest.params());
        cs.enable_txindex(None).unwrap();
        let queries = query_server(cs);
        let (r, e) = dispatch("getindexinfo", &json!([]), &snap, Some(&queries), None);
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
        );
        assert!(r.get("txindex").is_some());
        let (r, _) = dispatch(
            "getindexinfo",
            &json!(["coinstatsindex"]),
            &snap,
            Some(&queries),
            None,
        );
        assert_eq!(r, json!({}));
        // Non-string name → Core's -3; extra args → the -1 help throw.
        let (_, e) = dispatch("getindexinfo", &json!([5]), &snap, Some(&queries), None);
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);
        let (_, e) = dispatch(
            "getindexinfo",
            &json!(["a", "b"]),
            &snap,
            Some(&queries),
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
            let (_, e) = dispatch("gettxspendingprevout", &p, &snap, Some(&queries), None);
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
        let (r, e) = dispatch("getnetworkhashps", &json!([]), &snap, Some(&queries), None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r, json!(0));
        let (r, _) = dispatch(
            "getnetworkhashps",
            &json!([120, 0]),
            &snap,
            Some(&queries),
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
            let (_, e) = dispatch("getnetworkhashps", &p, &snap, Some(&queries), None);
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
        let (r, e) = dispatch("getnettotals", &json!([]), &snap, Some(&queries), None);
        assert!(e.is_none(), "{e:?}");
        assert_eq!(r["totalbytesrecv"], json!(0));
        assert_eq!(r["totalbytessent"], json!(0));
        assert!(r["timemillis"].as_u64().unwrap() > 0);
        assert_eq!(r["uploadtarget"]["target"], json!(0));
        assert_eq!(r["uploadtarget"]["timeframe"], json!(86400));
        assert_eq!(r["uploadtarget"]["serve_historical_blocks"], json!(true));
        let (_, e) = dispatch("getnettotals", &json!([1]), &snap, Some(&queries), None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
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
        );
        assert_eq!(r["success"], json!(false));
        // Unparseable → success:false with no error key.
        let (r, _) = dispatch(
            "addpeeraddress",
            &json!(["notanip", 8333]),
            &snap,
            Some(&queries),
            None,
        );
        assert_eq!(r, json!({"success": false}));

        let (r, e) = dispatch("getnodeaddresses", &json!([]), &snap, Some(&queries), None);
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
        );
        assert_eq!(r.as_array().unwrap().len(), 1);
        let (r, _) = dispatch(
            "getnodeaddresses",
            &json!([0, "onion"]),
            &snap,
            Some(&queries),
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
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getnodeaddresses",
            &json!([5, "bogus"]),
            &snap,
            Some(&queries),
            None,
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getnodeaddresses",
            &json!(["x"]),
            &snap,
            Some(&queries),
            None,
        );
        assert_eq!(e.unwrap().0, RPC_TYPE_ERROR);
        let (_, e) = dispatch("addpeeraddress", &json!([]), &snap, Some(&queries), None);
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
        let (_, e) = dispatch(
            "addpeeraddress",
            &json!(["1.2.3.4", 70000]),
            &snap,
            Some(&queries),
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);
    }
}

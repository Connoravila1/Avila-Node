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
//! There is no wallet, no `sendrawtransaction`, and no state mutation:
//! every answer is "what this node has itself observed", never a remote
//! claim. The single control method is `stop`, which flips the same
//! cancellation flag a GUI Stop button or SIGINT handler would.
//!
//! Not implemented (by design, this slice): HTTP keep-alive, chunked
//! encoding, TLS, authentication beyond localhost binding, batch
//! requests, txindex-backed `getrawtransaction`, and any method that
//! would mutate chain, pool or peer state.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::Duration;

use avila_consensus::arith::difficulty_from_compact;
use avila_consensus::chain::HeaderNode;
use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::hex;
use avila_consensus::transaction::{OutPoint, Script, Transaction};
use avila_p2p::manager::PeerManager;
use serde_json::{Value, json};

use crate::sync::SyncProgress;

/// The shared snapshot the sync loop publishes and the RPC server reads.
pub type SharedStatus = Arc<RwLock<SyncProgress>>;

/// The query body: read live state, produce a JSON result or a
/// JSON-RPC `(code, message)` error.
type QueryFn =
    Box<dyn FnOnce(&Chainstate, &PeerManager<TcpStream>) -> Result<Value, (i64, String)> + Send>;

/// A read-only query the sync loop answers against the live chainstate
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
    pub fn answer(self, cs: &Chainstate, mgr: &PeerManager<TcpStream>) {
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
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;
const RPC_INVALID_PARAMETER: i64 = -8;
const RPC_METHOD_NOT_FOUND: i64 = -32601;
const RPC_INVALID_PARAMS: i64 = -32602;

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
    f: impl FnOnce(&Chainstate, &PeerManager<TcpStream>) -> Result<Value, (i64, String)>
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

fn param<'a>(params: &'a Value, index: usize, name: &str) -> Option<&'a Value> {
    params.get(index).or_else(|| params.get(name))
}

fn missing_params(what: &str) -> (Value, Option<(i64, String)>) {
    (
        Value::Null,
        Some((RPC_INVALID_PARAMS, format!("missing parameter: {what}"))),
    )
}

/// Core's `GetDifficulty` (pow.cpp), matching bitcoind's printed value.
fn difficulty(bits: u32) -> f64 {
    difficulty_from_compact(avila_consensus::arith::CompactTarget(bits))
}

/// Whether `hash` sits on the active (connected, fully validated) chain.
fn on_active_chain(cs: &Chainstate, hash: &BlockHash, height: u32) -> bool {
    cs.chain().get(height as usize) == Some(hash)
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
        "difficulty": difficulty(node.header.bits.0),
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

/// Minimal `scriptPubKey`/`scriptSig` decode — hex only; type/address
/// classification is not implemented yet.
fn script_json(script: &avila_consensus::transaction::Script) -> Value {
    json!({"hex": hex::encode(script.as_bytes())})
}

/// A decoded transaction in Core's `getrawtransaction`/`getblock`
/// verbosity-2 shape, minus fields we don't compute yet (`asm`,
/// `type`, `addresses`, `vout` spends).
fn tx_json(tx: &Transaction) -> Value {
    let weight = tx.weight();
    json!({
        "txid": tx.txid().to_string(),
        "hash": tx.wtxid().to_string(),
        "version": tx.version,
        "size": tx.size_with_witness(),
        "vsize": weight.div_ceil(4),
        "weight": weight,
        "locktime": tx.lock_time,
        "vin": tx.inputs.iter().map(|input| {
            if input.previous_output.is_null() {
                json!({
                    "coinbase": hex::encode(input.script_sig.as_bytes()),
                    "sequence": input.sequence,
                })
            } else {
                let mut vin = json!({
                    "txid": input.previous_output.txid.to_string(),
                    "vout": input.previous_output.vout,
                    "scriptSig": script_json(&input.script_sig),
                    "sequence": input.sequence,
                });
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
                vin
            }
        }).collect::<Vec<_>>(),
        "vout": tx.outputs.iter().enumerate().map(|(n, out)| {
            json!({
                "value": out.value as f64 / 100_000_000.0,
                "n": n,
                "scriptPubKey": script_json(&out.script_pubkey),
            })
        }).collect::<Vec<_>>(),
    })
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
        "getblockchaininfo" => (
            json!({
                "chainheight": snap.connected_height,
                "blocks": snap.connected_height,
                "headers": snap.header_height,
                "bestblockhash": snap.recent.last().map(|(_, h)| h.to_string()),
                "peers": snap.peers,
                "verificationprogress": if snap.header_height > 0 {
                    snap.connected_height as f64 / snap.header_height.max(1) as f64
                } else {
                    0.0
                },
                "initialblockdownload": snap.connected_height < snap.header_height,
                "localobservation": true,
            }),
            None,
        ),
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
                            json!(block.transactions.iter().map(tx_json).collect::<Vec<_>>())
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
                if include_mempool {
                    let spent = mgr.mempool_ref().txids().iter().any(|id| {
                        mgr.mempool_ref().get(id).is_some_and(|tx| {
                            tx.inputs.iter().any(|i| i.previous_output == outpoint)
                        })
                    });
                    if spent {
                        return Ok(Value::Null);
                    }
                }
                match cs.utxo().get(&outpoint) {
                    None => Ok(Value::Null),
                    Some(coin) => {
                        let tip = cs.chain().len() as u32 - 1;
                        Ok(json!({
                            "bestblock": cs.tip_hash().to_string(),
                            "confirmations": tip - coin.height + 1,
                            "value": coin.out.value as f64 / 100_000_000.0,
                            "scriptPubKey": script_json(&coin.out.script_pubkey),
                            "coinbase": coin.coinbase,
                        }))
                    }
                }
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
                // Without txindex, Core serves mempool transactions and
                // transactions in an explicitly named block only.
                let found = if let Some(bh) = block_hash {
                    cs.body(&bh).and_then(|block| {
                        block
                            .transactions
                            .iter()
                            .find(|tx| tx.txid() == txid)
                            .cloned()
                            .map(|tx| (tx, Some(bh)))
                    })
                } else {
                    mgr.mempool_ref().get(&txid).cloned().map(|tx| (tx, None))
                };
                let Some((tx, in_block)) = found else {
                    return Err((
                        RPC_INVALID_ADDRESS_OR_KEY,
                        "No such mempool or blockchain transaction".into(),
                    ));
                };
                match verbosity {
                    0 => Ok(json!(hex::encode(&tx.encode()))),
                    1 | 2 => {
                        let mut out = tx_json(&tx);
                        if let Some(bh) = in_block
                            && let Some(node) = cs.tree().get(&bh)
                        {
                            let tip = cs.tree().tip().height;
                            out["blockhash"] = json!(bh.to_string());
                            out["confirmations"] = json!(i64::from(tip - node.height) + 1);
                            out["blocktime"] = json!(node.header.time);
                            out["time"] = json!(node.header.time);
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
        "getpeerinfo" => (
            Value::Array(
                snap.peer_details
                    .iter()
                    .map(|p| {
                        json!({
                            "id": p.id,
                            "addr": p.remote.map(|a| a.to_string()),
                            "inbound": p.inbound,
                            "handshake": p.established,
                            "claimed_height": p.start_height,
                            "subver": p.user_agent,
                            "headers_received": p.headers_received,
                            "blocks_received": p.blocks_received,
                            "in_flight": p.in_flight,
                            "connected_secs": p.connected_secs,
                            "idle_secs": p.idle_secs,
                        })
                    })
                    .collect(),
            ),
            None,
        ),
        "getmempoolinfo" => (
            json!({
                "size": snap.mempool.0,
                "orphans": snap.mempool.1,
                "fee_estimate_6blk_sat_per_kvb": snap.mempool.2,
            }),
            None,
        ),
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
            let mut out = json!({
                "capabilities": ["coinbasetxn", "workid", "coinbase/append"],
                "version": block.header.version,
                "rules": if flags.contains(avila_consensus::script::ScriptFlags::WITNESS) {
                    vec!["csv", "segwit"]
                } else {
                    vec!["csv"]
                },
                "previousblockhash": tip.to_string(),
                "transactions": txs,
                "coinbaseaux": {"flags": ""},
                "coinbasevalue": block.transactions[0].outputs[0].value,
                "longpollid": format!("{}{}", tip, now),
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
            // BIP22: the witness commitment script a miner must carry
            // when segwit transactions are included.
            if block.transactions[0].outputs.len() > 1 {
                out["default_witness_commitment"] = json!(hex::encode(
                    block.transactions[0].outputs[1].script_pubkey.as_bytes()
                ));
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
            let tip = cs.tip_hash();
            let node = cs.tree().tip();
            Ok(json!({
                "blocks": node.height,
                "currentblockweight": null,
                "currentblocktx": mgr.mempool_ref().len(),
                "difficulty": difficulty(node.header.bits.0),
                "bits": format!("{:08x}", node.header.bits.0),
                "target": node.header.bits.expand().value.to_hex(),
                "bestblockhash": tip.to_string(),
                "pooledtx": mgr.mempool_ref().len(),
                "network": format!("{:?}", cs.tree().params().network).to_lowercase(),
            }))
        }),
        "getnetworkinfo" => chain_query(queries, |cs, mgr| {
            Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "subversion": "/Avila:0.1.0/",
                "protocolversion": avila_p2p::message::PROTOCOL_VERSION,
                "network": format!("{:?}", cs.tree().params().network).to_lowercase(),
                "connections": mgr.len(),
                "relayfee": mgr.mempool_ref().min_relay_fee() as f64 / 100_000_000.0,
                "localservices": format!("{:016x}", avila_p2p::message::NODE_NETWORK | avila_p2p::message::NODE_WITNESS),
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
            let target = params
                .get(0)
                .or_else(|| params.get("conf_target"))
                .and_then(Value::as_u64)
                .unwrap_or(6) as u32;
            match snap.mempool.2 {
                Some(rate) if target == 6 => (json!({"feerate": rate, "blocks": 6}), None),
                _ => (
                    Value::Null,
                    Some((
                        RPC_INVALID_PARAMS,
                        "insufficient data — only the 6-block estimate is currently tracked".into(),
                    )),
                ),
            }
        }
        "help" => (
            json!(
                "avila-node JSON-RPC (read-only observations + stop):\n\
                 \x20 chain: getblockcount, getbestblockhash, getblockchaininfo, getchaintips,\n\
                 \x20   getblockhash <height>, getblockheader <hash> [verbose],\n\
                 \x20   getblock <hash> [verbosity 0-2], getrawtransaction <txid> [verbosity] [blockhash],\n\
                 \x20   gettxout <txid> <n> [include_mempool]\n\
                 \x20 mempool: getmempoolinfo, getrawmempool [verbose], getmempoolentry <txid>,\n\
                 \x20   getmempoolancestors|getmempooldescendants <txid> [verbose],\n\
                 \x20   getorphantxs, testmempoolaccept <rawtx | [rawtx,...]>\n\
                 \x20 mining: getblocktemplate, getmininginfo\n\
                 \x20 net:   getpeerinfo, getconnectioncount, getnetworkinfo\n\
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
        let (r, _) = snap_dispatch("getblockchaininfo", &Value::Null, &snap);
        assert_eq!(r["chainheight"], 120);
        assert_eq!(r["headers"], 140);
        let (r, _) = snap_dispatch("getmempoolinfo", &Value::Null, &snap);
        assert_eq!(r["size"], 5);
        let (r, _) = snap_dispatch("estimatesmartfee", &json!([6]), &snap);
        assert_eq!(r["feerate"], 2_000);
        // Non-6 targets honestly report insufficient data.
        let (_, e) = snap_dispatch("estimatesmartfee", &json!([12]), &snap);
        assert!(e.is_some());
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
        let mgr: PeerManager<TcpStream> = PeerManager::new(8);
        thread::spawn(move || {
            while let Ok(q) = rx.recv() {
                q.answer(&cs, &mgr);
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

        // The genesis header is indexed but its body was never stored
        // (genesis is never connected) — getblock says so honestly,
        // the same error Core gives for missing block data.
        let (_, e) = dispatch(
            "getblock",
            &json!([genesis, 1]),
            &snap,
            Some(&queries),
            None,
        );
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);

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
}

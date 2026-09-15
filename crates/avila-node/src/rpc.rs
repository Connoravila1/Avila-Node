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
//! requests, txindex-backed `getrawtransaction`, and the wallet
//! method surface.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::Duration;

use avila_consensus::arith::difficulty_from_compact;
use avila_consensus::chain::HeaderNode;
use avila_consensus::chainstate::Chainstate;
use avila_consensus::check::RuleError;
use avila_consensus::hash::{BlockHash, Txid};
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
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;
const RPC_INVALID_PARAMETER: i64 = -8;
const RPC_DESERIALIZATION_ERROR: i64 = -22;
const RPC_VERIFY_ERROR: i64 = -25;
const RPC_VERIFY_REJECTED: i64 = -26;
const RPC_METHOD_NOT_FOUND: i64 = -32601;
const RPC_INVALID_PARAMS: i64 = -32602;

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
/// address.
fn script_json(script: &avila_consensus::transaction::Script) -> Value {
    json!({
        "asm": script.asm(),
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
fn tx_json(tx: &Transaction, params: &avila_consensus::params::Params) -> Value {
    let weight = tx.weight();
    json!({
        "txid": tx.txid().to_string(),
        "hash": tx.wtxid().to_string(),
        "hex": hex::encode(&tx.encode()),
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
                "scriptPubKey": script_pubkey_json(&out.script_pubkey, params),
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
                "difficulty": difficulty(node.header.bits.0),
                "time": node.header.time,
                "mediantime": cs
                    .tree()
                    .median_time_past(&tip)
                    .unwrap_or(node.header.time),
                "verificationprogress": if best_header.height > 0 {
                    connected as f64 / best_header.height as f64
                } else {
                    1.0
                },
                "initialblockdownload": best_header.height > connected,
                "chainwork": node.chainwork.0.to_hex(),
                "size_on_disk": size_on_disk,
                "pruned": cs.store().and_then(|s| s.pruned_through()).is_some(),
                "warnings": [],
            }))
        }),
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
                                    .map(|tx| tx_json(tx, cs.tree().params()))
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
                // the documented -5.
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
                        let mut out = tx_json(&tx, cs.tree().params());
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
            let mut out = json!({
                // Core's modern capability set — `proposal` is the only
                // extension bitcoind 25+ advertises.
                "capabilities": ["proposal"],
                "version": block.header.version,
                "rules": rules,
                "vbavailable": {},
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
            // networkhashps — Core's GetNetworkHashPS(120, tip): chainwork
            // delta over the window divided by its time span; 0 when the
            // chain is shorter than the window or the window is
            // timestamp-degenerate.
            const HASHPS_LOOKUP: u32 = 120;
            let networkhashps = if node.height < HASHPS_LOOKUP {
                0.0
            } else {
                let start_h = node.height - HASHPS_LOOKUP;
                let base = cs.tree().get_ancestor(&tip, start_h);
                let (mut min_t, mut max_t) = (node.header.time, node.header.time);
                for h in start_h..node.height {
                    if let Some(n) = cs
                        .chain()
                        .get(h as usize)
                        .and_then(|hash| cs.tree().get(hash))
                    {
                        min_t = min_t.min(n.header.time);
                        max_t = max_t.max(n.header.time);
                    }
                }
                match base {
                    Some(base) if min_t != max_t => {
                        // Core: (workDiff as double) / timeDiff — a
                        // floating quotient, not integer division.
                        node.chainwork
                            .0
                            .checked_sub(base.chainwork.0)
                            .map(|w| w.to_f64() / f64::from(max_t - min_t))
                            .unwrap_or(0.0)
                    }
                    _ => 0.0,
                }
            };
            let mut out = json!({
                "blocks": node.height,
                "currentblocksize": current.as_ref().map(|t| t.block.encode().len()).unwrap_or(0),
                "currentblockweight": current.as_ref().map(|t| t.weight).unwrap_or(0),
                "currentblocktx": current.as_ref().map(|t| t.tx_count).unwrap_or(0),
                "difficulty": difficulty(node.header.bits.0),
                "bits": format!("{:08x}", node.header.bits.0),
                "target": node.header.bits.expand().value.to_hex(),
                "networkhashps": networkhashps,
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
            let target = params
                .get(0)
                .or_else(|| params.get("conf_target"))
                .and_then(Value::as_u64)
                .unwrap_or(6) as u32;
            chain_query(queries, move |_, mgr| {
                match mgr.mempool_ref().estimate_fee(target) {
                    // Core reports feerate in BTC/kvB; our estimator
                    // stores sat/kvB.
                    Some(rate) => Ok(json!({
                        "feerate": rate as f64 / 100_000_000.0,
                        "blocks": target,
                    })),
                    None => Err((
                        RPC_INVALID_PARAMS,
                        "insufficient data — no confirming samples seen for this target".into(),
                    )),
                }
            })
        }
        "help" => (
            json!(
                "avila-node JSON-RPC:\n\
                 \x20 chain: getblockcount, getbestblockhash, getblockchaininfo, getchaintips,\n\
                 \x20   getblockhash <height>, getblockheader <hash> [verbose],\n\
                 \x20   getblock <hash> [verbosity 0-2], getrawtransaction <txid> [verbosity] [blockhash],\n\
                 \x20   gettxout <txid> <n> [include_mempool], decodescript <hex>\n\
                 \x20 mempool: getmempoolinfo, getrawmempool [verbose], getmempoolentry <txid>,\n\
                 \x20   getmempoolancestors|getmempooldescendants <txid> [verbose],\n\
                 \x20   getorphantxs, testmempoolaccept <rawtx | [rawtx,...]>,\n\
                 \x20   sendrawtransaction <hex> [maxfeerate] [maxburnamount], savemempool\n\
                 \x20 mining: getblocktemplate, getmininginfo, submitblock <hex>,\n\
                 \x20   submitheader <hex>, generatetoaddress <n> <address> [maxtries],\n\
                 \x20   generateblock <output> [rawtx/txid,...]\n\
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

        // An empty pool has no confirmation samples — the estimate
        // says so rather than inventing a rate.
        let (_, e) = dispatch("estimatesmartfee", &json!([6]), &snap, Some(&queries), None);
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMS);

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
}

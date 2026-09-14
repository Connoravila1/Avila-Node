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
//! claim.
//!
//! Not implemented (by design, this slice): HTTP keep-alive, chunked
//! encoding, TLS, authentication beyond localhost binding, batch
//! requests, txindex-backed `getrawtransaction`, and any method that
//! would mutate state.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::time::Duration;

use avila_consensus::chain::{HeaderNode, HeaderTree};
use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::{BlockHash, Txid};
use avila_consensus::hex;
use avila_consensus::transaction::{OutPoint, Transaction};
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
/// chainstate through the sync loop for chain data methods.
///
/// # Errors
/// `io::Error` if the listener cannot bind.
pub fn serve(
    addr: SocketAddr,
    status: SharedStatus,
    queries: Option<QuerySender>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)?;
    Ok(thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let status = status.clone();
                    let queries = queries.clone();
                    thread::spawn(move || handle(stream, &status, queries.as_ref()));
                }
                Err(_) => continue,
            }
        }
    }))
}

/// JSON-RPC error codes Core uses.
const RPC_MISC_ERROR: i64 = -1;
const RPC_INVALID_ADDRESS_OR_KEY: i64 = -5;
const RPC_INVALID_PARAMETER: i64 = -8;
const RPC_METHOD_NOT_FOUND: i64 = -32601;
const RPC_INVALID_PARAMS: i64 = -32602;

fn handle(mut stream: TcpStream, status: &SharedStatus, queries: Option<&QuerySender>) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    // Read headers until the blank line, bounded.
    let mut content_length = 0usize;
    let mut read_bytes = 0usize;
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                read_bytes += n;
                if read_bytes > MAX_REQUEST {
                    return;
                }
                let lower = line.trim_end().to_lowercase();
                if let Some(rest) = lower.strip_prefix("content-length:") {
                    content_length = rest.trim().parse().unwrap_or(0);
                }
                if line.trim_end().is_empty() {
                    break;
                }
            }
        }
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
    let (result, error) = dispatch(method, &params, &snap, queries);
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

/// Core's `GetDifficulty` (pow.cpp) — the same f64 math on the compact
/// target, so the printed value matches bitcoind's exactly.
fn difficulty(bits: u32) -> f64 {
    let mut shift = ((bits >> 24) & 0xff) as i32;
    let mut diff = f64::from(0x0000ffff) / f64::from(bits & 0x00ffffff);
    while shift < 29 {
        diff *= 256.0;
        shift += 1;
    }
    while shift > 29 {
        diff /= 256.0;
        shift -= 1;
    }
    diff
}

/// Whether `hash` sits on the active (connected, fully validated) chain.
fn on_active_chain(tree: &HeaderTree, cs: &Chainstate, hash: &BlockHash, height: u32) -> bool {
    let _ = tree;
    cs.chain().get(height as usize) == Some(hash)
}

/// The Core-shaped header object shared by `getblockheader`/`getblock`.
fn header_json(cs: &Chainstate, node: &HeaderNode) -> Value {
    let hash = node.hash();
    let tip_height = cs.tree().tip().height;
    let active = on_active_chain(cs.tree(), cs, &hash, node.height);
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

fn dispatch(
    method: &str,
    params: &Value,
    snap: &SyncProgress,
    queries: Option<&QuerySender>,
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
                "avila-node JSON-RPC (read-only observations):\n\
                 \x20 getblockcount, getbestblockhash, getblockchaininfo,\n\
                 \x20 getblockhash <height>, getblockheader <hash> [verbose],\n\
                 \x20 getblock <hash> [verbosity 0-2], getrawtransaction <txid> [verbosity] [blockhash],\n\
                 \x20 gettxout <txid> <n> [include_mempool], getpeerinfo, getmempoolinfo,\n\
                 \x20 estimatesmartfee <target>, help"
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
        }
    }

    #[test]
    fn read_only_methods_answer_from_the_snapshot() {
        let snap = snap();
        let (r, e) = dispatch("getblockcount", &Value::Null, &snap, None);
        assert_eq!(r, json!(120));
        assert!(e.is_none());
        let (r, _) = dispatch("getblockchaininfo", &Value::Null, &snap, None);
        assert_eq!(r["chainheight"], 120);
        assert_eq!(r["headers"], 140);
        let (r, _) = dispatch("getmempoolinfo", &Value::Null, &snap, None);
        assert_eq!(r["size"], 5);
        let (r, _) = dispatch("estimatesmartfee", &json!([6]), &snap, None);
        assert_eq!(r["feerate"], 2_000);
        // Non-6 targets honestly report insufficient data.
        let (_, e) = dispatch("estimatesmartfee", &json!([12]), &snap, None);
        assert!(e.is_some());
        let (_, e) = dispatch("sendtoaddress", &Value::Null, &snap, None);
        assert_eq!(e.unwrap().0, RPC_METHOD_NOT_FOUND);
    }

    #[test]
    fn chain_methods_need_the_query_channel() {
        let snap = snap();
        let (_, e) = dispatch("getblockhash", &json!([0]), &snap, None);
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

        let (r, e) = dispatch("getblockhash", &json!([0]), &snap, Some(&queries));
        assert!(e.is_none());
        let genesis = r.as_str().unwrap().to_string();

        let (r, e) = dispatch("getblockheader", &json!([genesis]), &snap, Some(&queries));
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
        );
        assert!(e.is_none());
        assert_eq!(r.as_str().unwrap().len(), 160);

        // The genesis header is indexed but its body was never stored
        // (genesis is never connected) — getblock says so honestly,
        // the same error Core gives for missing block data.
        let (_, e) = dispatch("getblock", &json!([genesis, 1]), &snap, Some(&queries));
        assert_eq!(e.unwrap().0, RPC_MISC_ERROR);

        // Unknown heights/hashes get Core's error codes, not nulls.
        let (_, e) = dispatch("getblockhash", &json!([99]), &snap, Some(&queries));
        assert_eq!(e.unwrap().0, RPC_INVALID_PARAMETER);
        let (_, e) = dispatch(
            "getblockheader",
            &json!([BlockHash::from_bytes([9u8; 32]).to_string()]),
            &snap,
            Some(&queries),
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_ADDRESS_OR_KEY);

        // gettxout on a nonexistent outpoint is null (like Core).
        let (_, e) = dispatch(
            "gettxout",
            &json!([Txid::from_bytes([1u8; 32]).to_string(), 0]),
            &snap,
            Some(&queries),
        );
        assert!(e.is_none());
        let (r, _) = dispatch(
            "gettxout",
            &json!([Txid::from_bytes([1u8; 32]).to_string(), 0]),
            &snap,
            Some(&queries),
        );
        assert!(r.is_null());

        // No txindex and not in the mempool → Core's -5.
        let (_, e) = dispatch(
            "getrawtransaction",
            &json!([Txid::from_bytes([1u8; 32]).to_string()]),
            &snap,
            Some(&queries),
        );
        assert_eq!(e.unwrap().0, RPC_INVALID_ADDRESS_OR_KEY);
    }
}

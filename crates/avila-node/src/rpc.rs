//! A minimal JSON-RPC 1.0 query surface for the running node —
//! Core's `-rpcport` analog, scoped to *read-only* observations of the
//! last-published sync snapshot. There is no wallet, no `sendrawtransaction`,
//! and no state mutation: every answer is "what this node has itself
//! observed", never a remote claim.
//!
//! Not implemented (by design, this slice): HTTP keep-alive, chunked
//! encoding, TLS, authentication beyond localhost binding, batch
//! requests, and any method that would mutate state.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, RwLock};
use std::thread;

use serde_json::{Value, json};

use crate::sync::SyncProgress;

/// The shared snapshot the sync loop publishes and the RPC server reads.
pub type SharedStatus = Arc<RwLock<SyncProgress>>;

/// Request/response byte cap — RPC requests are small; a peer that
/// floods headers past this is disconnected.
const MAX_REQUEST: usize = 64 * 1024;

/// Spawns the RPC listener on its own thread. `status` is read per
/// request — answers reflect the most recent sync tick, not a live
/// call into the validator.
///
/// # Errors
/// `io::Error` if the listener cannot bind.
pub fn serve(addr: SocketAddr, status: SharedStatus) -> std::io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)?;
    Ok(thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let status = status.clone();
                    thread::spawn(move || handle(stream, &status));
                }
                Err(_) => continue,
            }
        }
    }))
}

/// JSON-RPC error codes Core uses.
const RPC_METHOD_NOT_FOUND: i64 = -32601;
const RPC_INVALID_PARAMS: i64 = -32602;

fn handle(mut stream: TcpStream, status: &SharedStatus) {
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
    let (result, error) = dispatch(method, &params, &snap);
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

fn dispatch(method: &str, params: &Value, snap: &SyncProgress) -> (Value, Option<(i64, String)>) {
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
                "bestblockhash": snap.recent.last().map(|(_, h)| h.to_string()),
                "headers": snap.header_height,
                "peers": snap.peers,
                "verificationprogress": if snap.header_height > 0 {
                    snap.connected_height as f64 / snap.header_height.max(1) as f64
                } else {
                    0.0
                },
                "localobservation": true,
            }),
            None,
        ),
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
                "avila-node JSON-RPC (read-only observations):\n  getblockcount, getbestblockhash, getblockchaininfo,\n  getpeerinfo, getmempoolinfo, estimatesmartfee <target>, help"
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
        let (r, e) = dispatch("getblockcount", &Value::Null, &snap);
        assert_eq!(r, json!(120));
        assert!(e.is_none());
        let (r, _) = dispatch("getblockchaininfo", &Value::Null, &snap);
        assert_eq!(r["chainheight"], 120);
        assert_eq!(r["headers"], 140);
        let (r, _) = dispatch("getmempoolinfo", &Value::Null, &snap);
        assert_eq!(r["size"], 5);
        let (r, _) = dispatch("estimatesmartfee", &json!([6]), &snap);
        assert_eq!(r["feerate"], 2_000);
        // Non-6 targets honestly report insufficient data.
        let (_, e) = dispatch("estimatesmartfee", &json!([12]), &snap);
        assert!(e.is_some());
        let (_, e) = dispatch("sendtoaddress", &Value::Null, &snap);
        assert_eq!(e.unwrap().0, RPC_METHOD_NOT_FOUND);
    }
}

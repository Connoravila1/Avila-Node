//! Bounded client workers for the GUI's attach-to-daemon mode.
//!
//! The GUI never opens a second chainstate in attach mode. All observations
//! and block inspection requests go through the daemon's authenticated RPC
//! endpoint. RPC credentials are read from the local cookie file for each
//! request and are never included in status, console, or error messages.

use avila_node::inspect::{
    BlockLookupResult, BlockTxDetailResult, MAX_TRANSACTION_PAGE, MAX_TX_DETAIL_PAGE,
};
use avila_node::sync::ControlMsg;
use eframe::egui::Context;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

const RPC_TIMEOUT: Duration = Duration::from_secs(3);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const MAX_CONSOLE_REQUEST_BYTES: usize = 8 * 1024;
const MAX_CONSOLE_RESPONSE_BYTES: usize = 64 * 1024;
const READ_ONLY_METHODS: &[&str] = &[
    "help",
    "getblockchaininfo",
    "getvalidationreport",
    "getnetworkinfo",
    "getnettotals",
    "getpeerinfo",
    "getmempoolinfo",
    "getchaintips",
    "getblockheader",
    "getblockhash",
    "getblockinspect",
    "getblocktxinspect",
    "getblockstats",
];

/// A set of attached-node observations gathered through sequential RPC
/// calls, not one atomic daemon snapshot. Optional RPCs remain `None` when
/// unavailable; callers must not replace unknown values with zeroes.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Raw `getblockchaininfo` result. In particular, `blocks` is connected
    /// height and `headers` is the best-header height.
    pub chain: Value,
    /// Raw `getvalidationreport` result, including its explicit coverage.
    pub validation: Value,
    /// Raw `getnettotals` result, if available.
    pub net: Option<Value>,
    /// Raw `getpeerinfo` result, if available.
    pub peers: Option<Value>,
    /// Raw `getnetworkinfo` result, if available.
    pub network: Option<Value>,
    /// Monotonic time captured after required calls succeed. Since RPCs run
    /// sequentially, the fields may describe slightly different instants.
    pub observed_at: Instant,
}

/// A read-only console call and its independently bounded response channel.
pub struct ConsoleRequest {
    pub method: String,
    pub params: Vec<Value>,
    pub reply: SyncSender<Result<Value, String>>,
}

/// Owns three lightweight RPC workers: status polling, private block
/// inspection, and bounded read-only console calls. Dropping it asks each
/// worker to stop. `RPC_TIMEOUT` applies independently to connection, read,
/// and write inactivity; it is not a whole-call deadline or cancellation.
pub struct Worker {
    pub control: Sender<ControlMsg>,
    pub updates: Receiver<Result<Snapshot, String>>,
    pub console: SyncSender<ConsoleRequest>,
    stop: Arc<AtomicBool>,
}

impl Worker {
    /// Start an attachment worker. Only loopback socket addresses are
    /// accepted. A missing cookie is a recoverable attach state: polling
    /// continues and retries cookie reads so a GUI opened before daemon
    /// startup can connect when the daemon creates its cookie. Address
    /// rejection is delivered as the first update without starting workers.
    pub fn start(addr: SocketAddr, data_dir: PathBuf, ctx: Context) -> Self {
        let (control_tx, control_rx) = mpsc::channel();
        let (updates_tx, updates_rx) = mpsc::sync_channel(1);
        let (console_tx, console_rx) = mpsc::sync_channel(2);
        let stop = Arc::new(AtomicBool::new(false));

        if !addr.ip().is_loopback() {
            let error = "Attach accepts loopback RPC addresses only.".to_owned();
            let _ = updates_tx.try_send(Err(error));
            stop.store(true, Ordering::Relaxed);
            return Self {
                control: control_tx,
                updates: updates_rx,
                console: console_tx,
                stop,
            };
        }

        let status_stop = Arc::clone(&stop);
        let status_ctx = ctx.clone();
        let status_data_dir = data_dir.clone();
        let status_updates = updates_tx.clone();
        let status_thread = thread::Builder::new()
            .name("avila-gui-attach-status".into())
            .spawn(move || {
                status_loop(
                    addr,
                    &status_data_dir,
                    status_stop,
                    status_ctx,
                    status_updates,
                );
            });
        if let Err(error) = status_thread {
            stop.store(true, Ordering::Relaxed);
            let _ = updates_tx.try_send(Err(format!(
                "Could not start attach status worker: {error}"
            )));
            return Self {
                control: control_tx,
                updates: updates_rx,
                console: console_tx,
                stop,
            };
        }

        let inspect_stop = Arc::clone(&stop);
        let inspect_ctx = ctx.clone();
        let inspect_data_dir = data_dir.clone();
        let inspect_thread = thread::Builder::new()
            .name("avila-gui-attach-inspect".into())
            .spawn(move || {
                inspect_loop(
                    addr,
                    &inspect_data_dir,
                    inspect_stop,
                    inspect_ctx,
                    control_rx,
                );
            });
        if let Err(error) = inspect_thread {
            stop.store(true, Ordering::Relaxed);
            let _ = updates_tx.try_send(Err(format!(
                "Could not start attach inspector worker: {error}"
            )));
            return Self {
                control: control_tx,
                updates: updates_rx,
                console: console_tx,
                stop,
            };
        }

        let console_stop = Arc::clone(&stop);
        let console_ctx = ctx;
        let console_thread = thread::Builder::new()
            .name("avila-gui-attach-console".into())
            .spawn(move || {
                console_loop(addr, &data_dir, console_stop, console_ctx, console_rx);
            });
        if let Err(error) = console_thread {
            stop.store(true, Ordering::Relaxed);
            let _ = updates_tx.try_send(Err(format!(
                "Could not start attach console worker: {error}"
            )));
        }

        Self {
            control: control_tx,
            updates: updates_rx,
            console: console_tx,
            stop,
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn status_loop(
    addr: SocketAddr,
    data_dir: &std::path::Path,
    stop: Arc<AtomicBool>,
    ctx: Context,
    updates: SyncSender<Result<Snapshot, String>>,
) {
    while !stop.load(Ordering::Relaxed) {
        let cycle_start = Instant::now();
        let result = (|| {
            // Exactly five calls per successful poll; optional panels stay
            // unknown when their individual calls fail.
            let chain = rpc_result(addr, data_dir, "getblockchaininfo", Vec::new())?;
            let validation = rpc_result(addr, data_dir, "getvalidationreport", Vec::new())?;
            let net = rpc_result(addr, data_dir, "getnettotals", Vec::new())
                .ok()
                .filter(|value| parse_network_totals(value).is_some());
            let peers = rpc_result(addr, data_dir, "getpeerinfo", Vec::new()).ok();
            let network = rpc_result(addr, data_dir, "getnetworkinfo", Vec::new()).ok();
            Ok(Snapshot {
                chain,
                validation,
                net,
                peers,
                network,
                observed_at: Instant::now(),
            })
        })();
        let _ = updates.try_send(result);
        ctx.request_repaint();

        let elapsed = cycle_start.elapsed();
        let mut left = POLL_INTERVAL.saturating_sub(elapsed);
        while !left.is_zero() && !stop.load(Ordering::Relaxed) {
            let pause = left.min(Duration::from_millis(100));
            thread::sleep(pause);
            left = left.saturating_sub(pause);
        }
    }
}

fn inspect_loop(
    addr: SocketAddr,
    data_dir: &std::path::Path,
    stop: Arc<AtomicBool>,
    ctx: Context,
    control: Receiver<ControlMsg>,
) {
    while !stop.load(Ordering::Relaxed) {
        match control.recv_timeout(Duration::from_millis(100)) {
            Ok(ControlMsg::InspectBlock {
                lookup,
                tx_offset,
                tx_limit,
                reply,
            }) => {
                let bounded_limit = tx_limit.clamp(1, MAX_TRANSACTION_PAGE);
                let lookup_value = match lookup {
                    avila_node::inspect::BlockLookup::Height(height) => json!(height),
                    avila_node::inspect::BlockLookup::Hash(hash) => json!(hash.to_string()),
                };
                let result = rpc_result(
                    addr,
                    data_dir,
                    "getblockinspect",
                    vec![lookup_value, json!(tx_offset), json!(bounded_limit)],
                )
                .and_then(|value| {
                    serde_json::from_value::<BlockLookupResult>(value).map_err(|_| {
                        "The daemon returned an invalid block-inspection response.".to_owned()
                    })
                })
                .unwrap_or_else(BlockLookupResult::Error);
                let _ = reply.try_send(result);
                ctx.request_repaint();
            }
            Ok(ControlMsg::InspectBlockTx {
                block_hash,
                txid,
                tx_index,
                input_offset,
                input_limit,
                output_offset,
                output_limit,
                reply,
            }) => {
                let result = rpc_result(
                    addr,
                    data_dir,
                    "getblocktxinspect",
                    vec![
                        json!(block_hash.to_string()),
                        json!(txid.to_string()),
                        json!(tx_index),
                        json!(input_offset),
                        json!(input_limit.clamp(1, MAX_TX_DETAIL_PAGE)),
                        json!(output_offset),
                        json!(output_limit.clamp(1, MAX_TX_DETAIL_PAGE)),
                    ],
                )
                .and_then(|value| {
                    serde_json::from_value::<BlockTxDetailResult>(value).map_err(|_| {
                        "The daemon returned an invalid transaction-inspection response.".to_owned()
                    })
                })
                .unwrap_or_else(BlockTxDetailResult::Error);
                let _ = reply.try_send(result);
                ctx.request_repaint();
            }
            Ok(ControlMsg::Set { .. }) => {
                // Attach mode has no local sync loop; reject live knob writes.
                // It deliberately does not translate them to RPC setters.
                ctx.request_repaint();
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn console_loop(
    addr: SocketAddr,
    data_dir: &std::path::Path,
    stop: Arc<AtomicBool>,
    ctx: Context,
    console: Receiver<ConsoleRequest>,
) {
    while !stop.load(Ordering::Relaxed) {
        let request = match console.recv_timeout(Duration::from_millis(100)) {
            Ok(request) => request,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let result = bounded_console_call(addr, data_dir, &request.method, &request.params);
        let _ = request.reply.try_send(result);
        ctx.request_repaint();
    }
}

fn bounded_console_call(
    addr: SocketAddr,
    data_dir: &std::path::Path,
    method: &str,
    params: &[Value],
) -> Result<Value, String> {
    if !READ_ONLY_METHODS.contains(&method) {
        return Err("This GUI console allows read-only RPC methods only.".into());
    }
    let params_value = Value::Array(params.to_vec());
    let param_bytes =
        serde_json::to_vec(&params_value).map_err(|_| "Invalid RPC parameters.".to_owned())?;
    let request_bytes = method.len().saturating_add(param_bytes.len());
    if request_bytes > MAX_CONSOLE_REQUEST_BYTES {
        return Err("RPC method and parameters exceed the 8 KiB request limit.".into());
    }
    let value = rpc_result(addr, data_dir, method, params.to_vec())?;
    // This matches the GUI display ceiling. It is checked after the RPC
    // helper's bounded HTTP response has been parsed (the transport itself
    // caps at 32 MiB).
    let response_size = serde_json::to_vec(&value)
        .map_err(|_| "RPC response could not be serialized.".to_owned())?
        .len();
    if response_size > MAX_CONSOLE_RESPONSE_BYTES {
        return Err("RPC response exceeds the 64 KiB display limit.".into());
    }
    Ok(value)
}

/// Parse the documented cumulative totals without turning missing or
/// malformed values into zero-valued traffic observations.
fn parse_network_totals(value: &Value) -> Option<(u64, u64)> {
    Some((
        value.get("totalbytesrecv")?.as_u64()?,
        value.get("totalbytessent")?.as_u64()?,
    ))
}

fn rpc_result(
    addr: SocketAddr,
    data_dir: &std::path::Path,
    method: &str,
    params: Vec<Value>,
) -> Result<Value, String> {
    if !addr.ip().is_loopback() {
        return Err("Attach accepts loopback RPC addresses only.".into());
    }
    // Re-read for every request so daemon cookie rotation takes effect;
    // neither token nor authorization header appears in errors or logs.
    let token = avila_node::rpc::read_cookie(data_dir)
        .map_err(|_| "Could not read the local RPC cookie.".to_owned())?;
    let auth = avila_node::rpc::cookie_auth_header(&token);
    let request = json!({
        "jsonrpc": "1.0",
        "id": "avila-gui-attach",
        "method": method,
        "params": params,
    });
    let response = avila_node::rpc::call_with_timeout(addr, Some(&auth), &request, RPC_TIMEOUT)?;
    if let Some(error) = response.get("error").filter(|e| !e.is_null()) {
        // Bound server-provided error text before it reaches a visible UI.
        let mut text = error.to_string();
        text.truncate(512);
        return Err(format!("RPC {method} failed: {text}"));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| format!("RPC {method} returned no result field."))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::Mutex;

    struct TestDataDir(PathBuf);

    impl TestDataDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "avila-attach-rpc-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDataDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fake_rpc_server(
        listener: TcpListener,
        expected_auth: String,
        stop: Arc<AtomicBool>,
        methods: Arc<Mutex<Vec<String>>>,
    ) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("avila-gui-fake-rpc".into())
            .spawn(move || {
                let _ = listener.set_nonblocking(true);
                let deadline = Instant::now() + Duration::from_secs(12);
                while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                    let (stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                        Err(_) => break,
                    };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let mut reader = BufReader::new(stream);
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        break;
                    }
                    let mut auth = None;
                    let mut content_len = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("authorization") {
                                auth = Some(value.trim().to_owned());
                            } else if name.eq_ignore_ascii_case("content-length") {
                                content_len = value.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    if auth.as_deref() != Some(expected_auth.as_str()) || content_len > 8 * 1024 {
                        // Do not print or assert-format the credential.
                        break;
                    }
                    let mut body = vec![0; content_len];
                    if reader.read_exact(&mut body).is_err() {
                        break;
                    }
                    let request: Value = match serde_json::from_slice(&body) {
                        Ok(value) => value,
                        Err(_) => break,
                    };
                    let method = request
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    methods.lock().unwrap().push(method.clone());
                    let result = match method.as_str() {
                        "getblockchaininfo" => json!({
                            "blocks": 321,
                            "headers": 325,
                            "bestblockhash": "00"
                        }),
                        "getvalidationreport" => json!({
                            "connected_height": 321,
                            "header_height": 325,
                            "coverage": { "state": "full_validation" }
                        }),
                        "getnettotals" => json!({
                            "totalbytesrecv": 1000,
                            "totalbytessent": 2000
                        }),
                        "getpeerinfo" => json!([]),
                        "getnetworkinfo" => json!({ "networkactive": true }),
                        "getblockinspect" => json!({ "status": "not_found" }),
                        "getblocktxinspect" => json!({ "status": "not_found" }),
                        _ => break,
                    };
                    let response = json!({
                        "result": result,
                        "error": null,
                        "id": request.get("id").cloned().unwrap_or(Value::Null),
                    })
                    .to_string();
                    let writer = reader.get_mut();
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    );
                    if writer
                        .write_all(header.as_bytes())
                        .and_then(|()| writer.write_all(response.as_bytes()))
                        .is_err()
                    {
                        break;
                    }
                }
            })
            .unwrap()
    }

    #[test]
    fn console_allowlist_rejects_mutating_methods_before_rpc() {
        let result = bounded_console_call(
            "127.0.0.1:1".parse().unwrap(),
            std::path::Path::new("/missing"),
            "stop",
            &[],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("read-only"));
    }

    #[test]
    fn console_bounds_parameters_before_rpc() {
        let oversized = Value::String("x".repeat(MAX_CONSOLE_REQUEST_BYTES));
        let result = bounded_console_call(
            "127.0.0.1:1".parse().unwrap(),
            std::path::Path::new("/missing"),
            "getblockhash",
            &[oversized],
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("8 KiB"));
    }

    #[test]
    fn read_only_allowlist_excludes_control_and_wallet_methods() {
        assert!(READ_ONLY_METHODS.contains(&"getblockchaininfo"));
        assert!(READ_ONLY_METHODS.contains(&"getblockinspect"));
        assert!(READ_ONLY_METHODS.contains(&"getblocktxinspect"));
        assert!(!READ_ONLY_METHODS.contains(&"stop"));
        assert!(!READ_ONLY_METHODS.contains(&"setban"));
        assert!(!READ_ONLY_METHODS.contains(&"sendtoaddress"));
    }

    #[test]
    fn network_totals_parser_preserves_unknown_and_accepts_cumulative_pair() {
        assert_eq!(parse_network_totals(&json!({})), None);
        assert_eq!(parse_network_totals(&json!({"totalbytesrecv": 1})), None);
        assert_eq!(
            parse_network_totals(&json!({
                "totalbytesrecv": 17,
                "totalbytessent": 29
            })),
            Some((17, 29))
        );
    }

    #[test]
    fn missing_cookie_is_a_retryable_poll_error() {
        let missing_data_dir = std::env::temp_dir().join(format!(
            "avila-attach-no-cookie-test-{}",
            std::process::id()
        ));
        let worker = Worker::start(
            "127.0.0.1:1".parse().unwrap(),
            missing_data_dir,
            Context::default(),
        );
        let first = worker.updates.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(first.unwrap_err().contains("local RPC cookie"));
        assert!(matches!(
            worker.updates.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn attach_recovers_cookie_and_decodes_status_and_inspection_rpc() {
        let data_dir = TestDataDir::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let methods = Arc::new(Mutex::new(Vec::new()));
        let worker = Worker::start(addr, data_dir.0.clone(), Context::default());

        // The client remains alive, reporting a missing-cookie error until
        // the daemon creates its cookie. The initial failure sends no RPC.
        let startup = worker.updates.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(startup.unwrap_err().contains("local RPC cookie"));
        let token = avila_node::rpc::write_cookie(&data_dir.0).unwrap();
        let expected_auth = avila_node::rpc::cookie_auth_header(&token);
        drop(token);

        let server_stop = Arc::clone(&worker.stop);
        let server_methods = Arc::clone(&methods);
        let server = fake_rpc_server(listener, expected_auth, server_stop, server_methods);
        let snapshot = worker
            .updates
            .recv_timeout(Duration::from_secs(7))
            .unwrap()
            .unwrap();
        assert_eq!(
            snapshot.chain.get("blocks").and_then(Value::as_u64),
            Some(321)
        );
        assert_eq!(
            snapshot.chain.get("headers").and_then(Value::as_u64),
            Some(325)
        );
        assert_eq!(
            snapshot
                .validation
                .pointer("/coverage/state")
                .and_then(Value::as_str),
            Some("full_validation")
        );
        assert_eq!(
            snapshot.net.as_ref().and_then(parse_network_totals),
            Some((1000, 2000))
        );

        let (reply, response) = mpsc::sync_channel(1);
        worker
            .control
            .send(ControlMsg::InspectBlock {
                lookup: avila_node::inspect::BlockLookup::Height(999),
                tx_offset: 0,
                tx_limit: 20,
                reply,
            })
            .unwrap();
        assert!(matches!(
            response.recv_timeout(Duration::from_secs(3)).unwrap(),
            BlockLookupResult::NotFound
        ));

        let (reply, response) = mpsc::sync_channel(1);
        worker
            .control
            .send(ControlMsg::InspectBlockTx {
                block_hash: avila_consensus::hash::BlockHash::from_bytes([3; 32]),
                txid: avila_consensus::hash::Txid::from_bytes([4; 32]),
                tx_index: 7,
                input_offset: 10,
                input_limit: u16::MAX,
                output_offset: 11,
                output_limit: u16::MAX,
                reply,
            })
            .unwrap();
        assert!(matches!(
            response.recv_timeout(Duration::from_secs(3)).unwrap(),
            BlockTxDetailResult::NotFound
        ));

        drop(worker);
        server.join().unwrap();
        let methods = methods.lock().unwrap();
        for required in [
            "getblockchaininfo",
            "getvalidationreport",
            "getnettotals",
            "getpeerinfo",
            "getnetworkinfo",
            "getblockinspect",
            "getblocktxinspect",
        ] {
            assert!(methods.iter().any(|method| method == required));
        }
    }

    #[test]
    fn non_loopback_is_rejected_without_starting_a_network_worker() {
        let worker = Worker::start(
            "192.0.2.1:18443".parse().unwrap(),
            PathBuf::from("/missing"),
            Context::default(),
        );
        let update = worker.updates.try_recv().unwrap();
        assert!(update.unwrap_err().contains("loopback"));
    }
}

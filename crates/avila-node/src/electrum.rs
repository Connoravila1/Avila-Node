//! Electrum-protocol service (`--electrum addr:port`).
//!
//! A newline-delimited JSON-RPC server over TCP implementing the
//! Electrum protocol method surface that real clients (Electrum,
//! Sparrow-style watchers, electrs consumers) drive:
//!
//! ```text
//! server.version / banner / ping / donation_address / features
//! blockchain.headers.subscribe            → {hex, height} + pushes
//! blockchain.block.header(s)              → raw headers, per height
//! blockchain.scripthash.subscribe         → status hash + pushes
//! blockchain.scripthash.get_balance       → {confirmed, unconfirmed}
//! blockchain.scripthash.get_history       → confirmed + mempool txs
//! blockchain.scripthash.get_mempool       → mempool entries only
//! blockchain.scripthash.listunspent       → unspent outputs
//! blockchain.transaction.get              → raw tx (mempool or index)
//! blockchain.transaction.get_merkle       → {merkle, block_height, pos}
//! blockchain.transaction.broadcast        → sendrawtransaction
//! blockchain.estimatefee / relayfee       → FeeEstimator / relay floor
//! mempool.get_fee_histogram               → [feerate, vsize] pairs
//! ```
//!
//! History comes from the chainstate's `ScripthashIndex` (enabled by
//! `--electrum`, persisted to `scindex.dat`). Subscriptions park on
//! the sync loop's `BlockWaiters` — a per-connection pump re-registers
//! after each notification. Unconfirmed transactions appear in
//! history/balance answers immediately; status-change notifications
//! fire per sync tick once the observed status actually differs.
//!
//! The protocol carries no authentication — binding is the boundary;
//! the CLI default (`127.0.0.1`) and the flag's explicit address are
//! the operator's choice.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use avila_consensus::chainstate::Chainstate;
use avila_consensus::hash::{Txid, sha256};
use avila_consensus::hex;
use avila_consensus::transaction::{OutPoint, Transaction};
use avila_p2p::manager::PeerManager;
use serde_json::{Value, json};

use crate::rpc::{BlockWaiters, QuerySender, SharedStatus};

/// One scripthash subscription's observable state — the pump compares
/// `status` across ticks; the check closure refreshes it.
struct SubCell {
    /// The check's comparison basis — the confirmed-history status
    /// hash the last notify() computed (mempool history is invisible
    /// to the check, which sees only the chainstate).
    confirmed_status: Option<String>,
    /// Set by the waiter's check closure when the status changed —
    /// the pump drains it into a notification.
    dirty: bool,
    /// True when the last `waiters.register` call for this cell was
    /// turned away (the node-wide `BlockWaiters` cap was full) — no
    /// check is running against it, so the pump polls it directly each
    /// tick instead of waiting on a wake that will never come.
    polling: bool,
}

/// Shared, mutable connection state — the pump thread and the reader
/// thread both reach it (subscriptions arrive mid-connection).
struct ConnState {
    /// scripthash → its subscription cell.
    subs: HashMap<[u8; 32], Arc<Mutex<SubCell>>>,
    /// `blockchain.headers.subscribe` cell — last tip hash notified.
    headers: Option<Arc<Mutex<SubCell>>>,
    /// Every registered sub's wake fires this channel — the pump then
    /// scans cells for dirtied status.
    wake_tx: mpsc::SyncSender<()>,
    /// The write half — pump and reader share it.
    writer: Mutex<TcpStream>,
}

/// Hard cap on concurrent Electrum connections. A loopback-by-default
/// personal/family node has no business serving unbounded clients;
/// past this the accept loop drops new sockets instead of spawning
/// unbounded threads (two per connection: reader + notification pump).
/// A conservative default, not a protocol value — worth exposing as a
/// CLI flag if operators need more.
const MAX_CONNECTIONS: usize = 64;

/// Cap on one JSON-RPC request line's accumulated length before its
/// terminating newline arrives. Generous for any real request (the
/// largest is a `blockchain.transaction.broadcast`'s raw-tx hex), but
/// bounded: without it, a client that never sends `\n` — trickling
/// bytes slowly enough to keep beating the per-read timeout — can grow
/// the connection's buffer without limit.
const MAX_LINE_LEN: usize = 1024 * 1024;

/// Cap on a blocking write to the client. Pairs with the read
/// timeout: without it, a peer that stops reading its socket can wedge
/// `send()` forever while it holds the connection's locks, starving
/// the reader and pump threads that share them.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Runs the Electrum server on `addr` until `cancel` flips. Returns
/// the listener's join handle.
///
/// # Errors
/// `io::Error` if the listener cannot bind.
pub fn serve(
    addr: SocketAddr,
    queries: QuerySender,
    waiters: Arc<BlockWaiters>,
    status: SharedStatus,
    cancel: Arc<AtomicBool>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)?;
    // Nonblocking accept so `cancel` polls between connections.
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        accept_loop(listener, queries, waiters, status, cancel);
    }))
}

/// Holds one connection slot and gives it back when the connection's
/// thread ends — by panic too, which would otherwise leak the slot
/// until the accept loop turned everyone away.
struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The listener's accept loop — split out from [`serve`] so tests can
/// drive it against a listener bound to an OS-chosen port (`serve`
/// itself never hands the bound address back to the caller).
fn accept_loop(
    listener: TcpListener,
    queries: QuerySender,
    waiters: Arc<BlockWaiters>,
    status: SharedStatus,
    cancel: Arc<AtomicBool>,
) {
    let conns = Arc::new(AtomicUsize::new(0));
    while !cancel.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _peer)) => {
                if conns.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    // Over the cap — drop the socket rather than spawn
                    // another unbounded pair of threads.
                    drop(stream);
                    continue;
                }
                conns.fetch_add(1, Ordering::Relaxed);
                let queries = queries.clone();
                let waiters = waiters.clone();
                let status = status.clone();
                let cancel = cancel.clone();
                let slot = Slot(conns.clone());
                thread::spawn(move || {
                    let _slot = slot;
                    handle(stream, queries, waiters, status, cancel);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// The Electrum status hash for a history: `SHA256` over the
/// concatenation of `tx_hash:height:` for each entry in order —
/// mempool entries at height 0 (confirmed parents) or -1 (unconfirmed
/// parents). Empty history → `None`.
fn status_hash(entries: &[(i64, String)]) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let mut acc = String::new();
    for (height, txid) in entries {
        acc.push_str(&format!("{txid}:{height}:"));
    }
    Some(hex::encode(&sha256(acc.as_bytes())))
}

/// The history list Electrum serves — confirmed entries sorted by
/// (height, position), mempool entries last (height 0 or -1 per the
/// parent-confirmed rule). `None` when the index is off.
fn history_entries(
    cs: &Chainstate,
    mp: &avila_mempool::Mempool,
    sh: &[u8; 32],
) -> Option<Vec<(i64, String)>> {
    if !cs.scripthash_index_enabled() {
        return None;
    }
    let mut out: Vec<(i64, String)> = cs
        .scripthash_history(sh)
        .unwrap_or(&[])
        .iter()
        .map(|(h, _pos, txid)| (i64::from(*h), txid.to_string()))
        .collect();
    out.sort_by_key(|(h, _)| *h);
    // Mempool: every tx creating an output to the script, or spending
    // a tracked outpoint. Height -1 when any parent is unconfirmed.
    // Borrow — a full pool cloned per query is a memory-churn DoS.
    // `txids` are the map keys — reusing them avoids rehashing every tx.
    let txids = mp.txids();
    let mempool: Vec<&Transaction> = txids.iter().filter_map(|t| mp.get(t)).collect();
    let mempool_ids: std::collections::HashSet<Txid> = txids.iter().copied().collect();
    let mut seen: std::collections::HashSet<Txid> =
        out.iter().map(|(_, t)| parse_txid(t)).collect();
    for tx in &mempool {
        let touches = tx
            .outputs
            .iter()
            .any(|o| sha256(o.script_pubkey.as_bytes()) == *sh)
            || tx.inputs.iter().any(|i| {
                // A mempool spend touches the script if its prevout's
                // script hashes to it — the UTXO set carries the coin.
                cs.utxo()
                    .get(&i.previous_output)
                    .is_some_and(|c| sha256(c.out.script_pubkey.as_bytes()) == *sh)
            });
        if touches && seen.insert(tx.txid()) {
            let unconfirmed_parent = tx
                .inputs
                .iter()
                .any(|i| mempool_ids.contains(&i.previous_output.txid));
            out.push((
                if unconfirmed_parent { -1 } else { 0 },
                tx.txid().to_string(),
            ));
        }
    }
    Some(out)
}

fn parse_txid(s: &str) -> Txid {
    let mut b = hex::decode(s).unwrap_or_default();
    b.reverse();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b[..32.min(b.len())]);
    Txid::from_bytes(a)
}

fn reply(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "result": result, "id": id})
}

fn reply_err(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": id})
}

/// One connection: the reader thread dispatches requests; the pump
/// thread turns waiter wakes into subscription notifications.
fn handle(
    stream: TcpStream,
    queries: QuerySender,
    waiters: Arc<BlockWaiters>,
    status: SharedStatus,
    cancel: Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let Ok(writer) = stream.try_clone() else {
        return;
    };
    // A client that stops reading must not be able to wedge `send()`
    // (and the connection-wide locks it holds while writing) forever.
    let _ = writer.set_write_timeout(Some(WRITE_TIMEOUT));
    let (wake_tx, wake_rx) = mpsc::sync_channel::<()>(64);
    let state = Arc::new(Mutex::new(ConnState {
        subs: HashMap::new(),
        headers: None,
        wake_tx: wake_tx.clone(),
        writer: Mutex::new(writer),
    }));

    // The pump: a waiter wake (or a 100ms tick) drains dirty cells into
    // notifications, then re-registers each live subscription.
    {
        let state = state.clone();
        let queries = queries.clone();
        let waiters = waiters.clone();
        let cancel = cancel.clone();
        thread::spawn(move || {
            // `while let` can't express this: timeout ticks the pump
            // too — only `Disconnected` exits.
            #[allow(clippy::while_let_loop)]
            loop {
                match wake_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                pump_notifications(&state, &queries, &waiters);
            }
        });
    }

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        // Bound this attempt to what's left of the line's budget — a
        // fresh `Take` each iteration so a client trickling bytes just
        // under the read timeout (never actually erroring) still can't
        // grow `line` past MAX_LINE_LEN within a single call.
        let remaining = MAX_LINE_LEN.saturating_sub(line.len()) as u64;
        match reader.by_ref().take(remaining).read_line(&mut line) {
            Ok(_) if line.ends_with('\n') => {}
            Ok(_) => break, // EOF mid-line, or the line hit MAX_LINE_LEN
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Idle read window — the subscription lifetime is the
                // connection's, so keep waiting. Any partial line
                // already read stays put (and still capped) for the
                // next attempt.
                continue;
            }
            Err(_) => break,
        }
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let this_line = std::mem::take(&mut line);
        if this_line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(this_line.trim()) {
            Ok(v) => v,
            Err(_) => {
                send(&state, &reply_err(&Value::Null, -32700, "parse error"));
                continue;
            }
        };
        let method = req["method"].as_str().unwrap_or("").to_string();
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let params = req.get("params").cloned().unwrap_or(Value::Array(vec![]));
        let out = dispatch(&method, &params, &id, &state, &queries, &waiters, &status);
        send(&state, &out);
        if cancel.load(Ordering::Relaxed) {
            break;
        }
    }
    // Connection closed — drop the waiters' interest so notify()
    // stops spending ticks on this client.
    if let Ok(mut st) = state.lock() {
        st.subs.clear();
        st.headers = None;
    }
}

fn send(state: &Arc<Mutex<ConnState>>, v: &Value) {
    if let Ok(st) = state.lock()
        && let Ok(mut w) = st.writer.lock()
    {
        let _ = writeln!(w, "{}", serde_json::to_string(v).unwrap_or_default());
        let _ = w.flush();
    }
}

/// The full-history status hash (confirmed + mempool) for `sh` —
/// what a notification carries, matching a fresh subscribe reply.
fn full_status(queries: &QuerySender, sh: &[u8; 32]) -> Option<String> {
    let sh2 = *sh;
    let (query, rx) = crate::rpc::ChainQuery::new(move |cs, mgr| {
        Ok(json!(status_hash(
            &history_entries(cs, mgr.mempool(), &sh2).unwrap_or_default()
        )))
    });
    if queries.send(query).is_err() {
        return None;
    }
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(v)) => v.as_str().map(str::to_string),
        _ => None,
    }
}

/// After a wake: emit a notification for every cell whose status
/// changed, then re-register the subscriptions for the next tick.
fn pump_notifications(
    state: &Arc<Mutex<ConnState>>,
    queries: &QuerySender,
    waiters: &Arc<BlockWaiters>,
) {
    let (subs, headers, wake_tx) = {
        let Ok(st) = state.lock() else { return };
        (
            st.subs
                .iter()
                .map(|(k, v)| (*k, v.clone()))
                .collect::<Vec<_>>(),
            st.headers.clone(),
            st.wake_tx.clone(),
        )
    };
    for (sh, cell) in subs {
        // No waiter is watching this cell (its last registration hit
        // the node-wide cap) — poll it directly on this tick rather
        // than wait on a wake that will never come.
        if cell.lock().map(|c| c.polling).unwrap_or(false) {
            poll_script(queries, sh, &cell);
        }
        let fired = cell.lock().map(|c| c.dirty).unwrap_or(false);
        if !fired {
            continue; // its waiter is still parked — no re-register
        }
        if let Ok(mut c) = cell.lock() {
            c.dirty = false;
            drop(c);
            // Emit the FULL status — mempool entries included — so the
            // notification matches what a fresh subscribe would say.
            let status = full_status(queries, &sh);
            let note = json!({
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.subscribe",
                "params": [format_scripthash(&sh), status],
            });
            send(state, &note);
        }
        // The waiter consumed itself when it fired — park a fresh one
        // (or, if the cap is still full, fall back to polling again).
        reregister_script(sh, &cell, waiters, wake_tx.clone());
    }
    if let Some(cell) = headers {
        if cell.lock().map(|c| c.polling).unwrap_or(false) {
            poll_headers(queries, &cell);
        }
        let fired = cell.lock().map(|c| c.dirty).unwrap_or(false);
        if fired {
            if let Ok(mut c) = cell.lock() {
                c.dirty = false;
                // status is "hex:height" — the notification's param
                // object.
                let status = c.confirmed_status.clone().unwrap_or_default();
                drop(c);
                let (hex_hdr, height) = status
                    .rsplit_once(':')
                    .map(|(h, ht)| (h, ht.parse::<i64>().unwrap_or(0)))
                    .unwrap_or_default();
                let note = json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.headers.subscribe",
                    "params": [{
                        "hex": hex_hdr,
                        "height": height,
                    }],
                });
                send(state, &note);
            }
            reregister_headers(&cell, waiters, wake_tx);
        }
    }
}

/// Recomputes `sh`'s status against the live chain and marks its cell
/// dirty on a change — the same comparison a registered waiter's check
/// would run, driven instead by the pump's own tick because the last
/// `waiters.register` attempt found the node-wide cap full.
fn poll_script(queries: &QuerySender, sh: [u8; 32], cell: &Arc<Mutex<SubCell>>) {
    let new = full_status(queries, &sh);
    if let Ok(mut c) = cell.lock()
        && c.confirmed_status != new
    {
        c.confirmed_status = new;
        c.dirty = true;
    }
}

/// `poll_script`'s counterpart for `blockchain.headers.subscribe`.
fn poll_headers(queries: &QuerySender, cell: &Arc<Mutex<SubCell>>) {
    let (query, rx) = crate::rpc::ChainQuery::new(move |cs, _mgr| Ok(json!(header_status(cs))));
    if queries.send(query).is_err() {
        return;
    }
    let Ok(Ok(new)) = rx.recv_timeout(Duration::from_secs(5)) else {
        return;
    };
    let new = new.as_str().map(str::to_string);
    if let Ok(mut c) = cell.lock()
        && c.confirmed_status != new
    {
        c.confirmed_status = new;
        c.dirty = true;
    }
}

/// The current tip's `"hex:height"` status string — what
/// `blockchain.headers.subscribe` compares across ticks.
fn header_status(cs: &Chainstate) -> String {
    let tip = cs.tip_hash();
    let height = cs.chain().len() as i64 - 1;
    let hex_hdr = cs
        .tree()
        .get(&tip)
        .map(|n| hex::encode(&n.header.encode()))
        .unwrap_or_default();
    format!("{hex_hdr}:{height}")
}

/// Registers a script subscription's waiter — the check recomputes
/// the status hash against the live chainstate and fires when it
/// differs from what the client was last told. `BlockWaiters::register`
/// can turn the registration away once the node-wide cap (rpc.rs's
/// `MAX_BLOCK_WAITERS`) is full; rather than silently drop the
/// subscription's updates, that marks the cell for direct polling on
/// the pump's own tick until a slot frees up.
fn reregister_script(
    sh: [u8; 32],
    cell: &Arc<Mutex<SubCell>>,
    waiters: &Arc<BlockWaiters>,
    wake_tx: mpsc::SyncSender<()>,
) {
    let check_cell = cell.clone();
    let armed = waiters.register(
        Box::new(move |cs: &Chainstate, mp: &avila_mempool::Mempool| {
            // The full Electrum status — confirmed history plus
            // mempool rows — so a mempool tx touching the script fires
            // the subscription without waiting for a block.
            let entries = history_entries(cs, mp, &sh).unwrap_or_default();
            let new = status_hash(&entries);
            let Ok(mut c) = check_cell.lock() else {
                return false;
            };
            if c.confirmed_status != new {
                c.confirmed_status = new;
                c.dirty = true;
                true
            } else {
                false
            }
        }),
        wake_tx,
    );
    if let Ok(mut c) = cell.lock() {
        c.polling = !armed;
    }
}

/// [`reregister_script`]'s counterpart for `blockchain.headers.subscribe`.
fn reregister_headers(
    cell: &Arc<Mutex<SubCell>>,
    waiters: &Arc<BlockWaiters>,
    wake_tx: mpsc::SyncSender<()>,
) {
    let check_cell = cell.clone();
    let armed = waiters.register(
        Box::new(move |cs: &Chainstate, _mp: &avila_mempool::Mempool| {
            let new = header_status(cs);
            let Ok(mut c) = check_cell.lock() else {
                return false;
            };
            if c.confirmed_status.as_deref() != Some(new.as_str()) {
                c.confirmed_status = Some(new);
                c.dirty = true;
                true
            } else {
                false
            }
        }),
        wake_tx,
    );
    if let Ok(mut c) = cell.lock() {
        c.polling = !armed;
    }
}

fn dispatch(
    method: &str,
    params: &Value,
    id: &Value,
    state: &Arc<Mutex<ConnState>>,
    queries: &QuerySender,
    waiters: &Arc<BlockWaiters>,
    status: &SharedStatus,
) -> Value {
    let arr = params.as_array().map(Vec::as_slice).unwrap_or(&[]);
    match method {
        "server.version" => reply(id, json!(["avila-node 0.1.0", ["1.4", "1.4.2"]])),
        "server.ping" => reply(id, Value::Null),
        "server.banner" => reply(id, json!("Avila-Node — Electrum protocol service")),
        "server.donation_address" => reply(id, json!("")),
        "server.features" => {
            let _ = status;
            chain_value(queries, id, |cs, _mgr, id: Value| {
                let id = &id;
                let genesis = cs.chain().first().copied();
                reply(
                    id,
                    json!({
                        "genesis_hash": genesis.map(|h| h.to_string()).unwrap_or_default(),
                        "hosts": {},
                        "protocol_min": "1.4",
                        "protocol_max": "1.4.2",
                        "pruning": "-",
                        "server_version": "avila-node 0.1.0",
                        "hash_function": "sha256",
                        "services": [],
                    }),
                )
            })
        }
        "blockchain.headers.subscribe" => {
            let cell = Arc::new(Mutex::new(SubCell {
                confirmed_status: None,
                dirty: false,
                polling: false,
            }));
            let cell2 = cell.clone();
            if let Ok(mut st) = state.lock() {
                st.headers = Some(cell.clone());
            }
            // The query seeds the cell with the delivered tip — the
            // waiter registers after it so the first tick can't
            // re-notify what the reply already said.
            let out = chain_value(queries, id, move |cs, _mgr, id: Value| {
                let id = &id;
                let tip = cs.tip_hash();
                let height = cs.chain().len() as i64 - 1;
                let hex_hdr = cs
                    .tree()
                    .get(&tip)
                    .map(|n| hex::encode(&n.header.encode()))
                    .unwrap_or_default();
                if let Ok(mut c) = cell.lock() {
                    c.confirmed_status = Some(format!("{hex_hdr}:{height}"));
                }
                if hex_hdr.is_empty() {
                    reply(id, json!({"hex": "", "height": -1}))
                } else {
                    reply(id, json!({"hex": hex_hdr, "height": height}))
                }
            });
            let wake_tx = state
                .lock()
                .map(|st| st.wake_tx.clone())
                .unwrap_or_else(|_| mpsc::sync_channel(1).0);
            reregister_headers(&cell2, waiters, wake_tx);
            out
        }
        "blockchain.block.header" => {
            let Some(height) = arr.first().and_then(Value::as_u64) else {
                return reply_err(id, 1, "missing height");
            };
            chain_value(queries, id, move |cs, _mgr, id: Value| {
                let id = &id;
                match cs.chain().get(height as usize) {
                    Some(hash) => match cs.tree().get(hash) {
                        Some(n) => reply(id, json!(hex::encode(&n.header.encode()))),
                        None => reply_err(id, 1, "header not found"),
                    },
                    None => reply_err(id, 1, "height out of range"),
                }
            })
        }
        "blockchain.block.headers" => {
            let start = arr.first().and_then(Value::as_u64).unwrap_or(0);
            let count = arr.get(1).and_then(Value::as_u64).unwrap_or(1);
            chain_value(queries, id, move |cs, _mgr, id: Value| {
                let id = &id;
                let tip = cs.chain().len() as u64;
                let avail = tip.saturating_sub(start).min(count);
                let mut raw = Vec::with_capacity((avail * 80) as usize);
                for h in start..start + avail {
                    let hash = &cs.chain()[h as usize];
                    if let Some(n) = cs.tree().get(hash) {
                        raw.extend_from_slice(&n.header.encode());
                    }
                }
                reply(
                    id,
                    json!({
                        "count": avail,
                        "hex": hex::encode(&raw),
                        "max": 2016,
                    }),
                )
            })
        }
        "blockchain.scripthash.subscribe" => {
            let Some(sh) = arr
                .first()
                .and_then(Value::as_str)
                .and_then(parse_scripthash)
            else {
                return reply_err(id, 1, "invalid scripthash");
            };
            let cell = Arc::new(Mutex::new(SubCell {
                confirmed_status: None,
                dirty: false,
                polling: false,
            }));
            let cell2 = cell.clone();
            if let Ok(mut st) = state.lock() {
                st.subs.insert(sh, cell.clone());
            }
            // Answer with the current status immediately (spec) — the
            // query also seeds the cell, then the waiter registers so
            // the first tick can't re-notify a status already sent.
            let out = chain_value(queries, id, move |cs, mgr, id: Value| {
                let id = &id;
                let entries = history_entries(cs, mgr.mempool(), &sh).unwrap_or_default();
                let status = status_hash(&entries);
                // The check compares confirmed history only — seed that
                // basis separately so mempool entries can't fake a change.
                let confirmed: Vec<(i64, String)> =
                    entries.iter().filter(|(h, _)| *h > 0).cloned().collect();
                if let Ok(mut c) = cell.lock() {
                    c.confirmed_status = status_hash(&confirmed);
                }
                reply(id, status.map(Value::from).unwrap_or(Value::Null))
            });
            let wake_tx = state
                .lock()
                .map(|st| st.wake_tx.clone())
                .unwrap_or_else(|_| mpsc::sync_channel(1).0);
            reregister_script(sh, &cell2, waiters, wake_tx);
            out
        }
        "blockchain.scripthash.get_balance" => {
            let Some(sh) = arr
                .first()
                .and_then(Value::as_str)
                .and_then(parse_scripthash)
            else {
                return reply_err(id, 1, "invalid scripthash");
            };
            chain_value(queries, id, move |cs, mgr, id: Value| {
                let id = &id;
                let mut confirmed: i64 = 0;
                let mut unconfirmed: i64 = 0;
                // Unspent confirmed outputs to the script.
                if let Some(hist) = cs.scripthash_history(&sh) {
                    for (h, pos, txid) in hist {
                        // (height, position) locates the tx — the
                        // txindex isn't required for wallet queries.
                        let Some(tx) = cs
                            .chain()
                            .get(*h as usize)
                            .and_then(|bh| cs.body(bh))
                            .and_then(|b| b.transactions.get(*pos as usize).cloned())
                        else {
                            continue;
                        };
                        for (vout, out) in tx.outputs.iter().enumerate() {
                            if sha256(out.script_pubkey.as_bytes()) != sh {
                                continue;
                            }
                            let op = OutPoint {
                                txid: *txid,
                                vout: vout as u32,
                            };
                            if cs.utxo().get(&op).is_some() {
                                confirmed += out.value;
                            }
                        }
                    }
                }
                // Mempool: outputs to the script minus mempool spends of
                // the script's confirmed outputs.
                let mempool: Vec<Transaction> = mgr
                    .mempool()
                    .txids()
                    .iter()
                    .filter_map(|t| mgr.mempool().get(t).cloned())
                    .collect();
                let spent: std::collections::HashSet<OutPoint> = mempool
                    .iter()
                    .flat_map(|t| t.inputs.iter().map(|i| i.previous_output))
                    .collect();
                if let Some(hist) = cs.scripthash_history(&sh) {
                    for (h, pos, txid) in hist {
                        let Some(tx) = cs
                            .chain()
                            .get(*h as usize)
                            .and_then(|bh| cs.body(bh))
                            .and_then(|b| b.transactions.get(*pos as usize).cloned())
                        else {
                            continue;
                        };
                        for (vout, out) in tx.outputs.iter().enumerate() {
                            if sha256(out.script_pubkey.as_bytes()) != sh {
                                continue;
                            }
                            let op = OutPoint {
                                txid: *txid,
                                vout: vout as u32,
                            };
                            if cs.utxo().get(&op).is_some() && spent.contains(&op) {
                                unconfirmed -= out.value;
                            }
                        }
                    }
                }
                for tx in &mempool {
                    for (vout, out) in tx.outputs.iter().enumerate() {
                        if sha256(out.script_pubkey.as_bytes()) != sh {
                            continue;
                        }
                        let op = OutPoint {
                            txid: tx.txid(),
                            vout: vout as u32,
                        };
                        if !spent.contains(&op) {
                            unconfirmed += out.value;
                        }
                    }
                }
                reply(
                    id,
                    json!({"confirmed": confirmed, "unconfirmed": unconfirmed}),
                )
            })
        }
        "blockchain.scripthash.get_history" | "blockchain.scripthash.get_mempool" => {
            let Some(sh) = arr
                .first()
                .and_then(Value::as_str)
                .and_then(parse_scripthash)
            else {
                return reply_err(id, 1, "invalid scripthash");
            };
            let mempool_only = method.ends_with("get_mempool");
            chain_value(queries, id, move |cs, mgr, id: Value| {
                let id = &id;
                let Some(entries) = history_entries(cs, mgr.mempool(), &sh) else {
                    return reply_err(
                        id,
                        1,
                        "scripthash index unavailable — start with --electrum",
                    );
                };
                let rows: Vec<Value> = entries
                    .iter()
                    .filter(|(h, _)| !mempool_only || *h <= 0)
                    .map(|(h, t)| json!({"height": h, "tx_hash": t}))
                    .collect();
                reply(id, json!(rows))
            })
        }
        "blockchain.scripthash.listunspent" => {
            let Some(sh) = arr
                .first()
                .and_then(Value::as_str)
                .and_then(parse_scripthash)
            else {
                return reply_err(id, 1, "invalid scripthash");
            };
            chain_value(queries, id, move |cs, mgr, id: Value| {
                let id = &id;
                let mut rows: Vec<Value> = Vec::new();
                if let Some(hist) = cs.scripthash_history(&sh) {
                    for (h, pos, txid) in hist {
                        let Some(tx) = cs
                            .chain()
                            .get(*h as usize)
                            .and_then(|bh| cs.body(bh))
                            .and_then(|b| b.transactions.get(*pos as usize).cloned())
                        else {
                            continue;
                        };
                        for (vout, out) in tx.outputs.iter().enumerate() {
                            if sha256(out.script_pubkey.as_bytes()) != sh {
                                continue;
                            }
                            let op = OutPoint {
                                txid: *txid,
                                vout: vout as u32,
                            };
                            if cs.utxo().get(&op).is_some() {
                                rows.push(json!({
                                    "tx_hash": txid.to_string(),
                                    "tx_pos": vout,
                                    "height": h,
                                    "value": out.value,
                                }));
                            }
                        }
                    }
                }
                // Mempool-created unspent outputs to the script.
                let mempool: Vec<Transaction> = mgr
                    .mempool()
                    .txids()
                    .iter()
                    .filter_map(|t| mgr.mempool().get(t).cloned())
                    .collect();
                let mempool_spent: std::collections::HashSet<OutPoint> = mempool
                    .iter()
                    .flat_map(|t| t.inputs.iter().map(|i| i.previous_output))
                    .collect();
                rows.retain(|r| {
                    let op = OutPoint {
                        txid: parse_txid(r["tx_hash"].as_str().unwrap_or_default()),
                        vout: r["tx_pos"].as_u64().unwrap_or(0) as u32,
                    };
                    !mempool_spent.contains(&op)
                });
                for tx in &mempool {
                    for (vout, out) in tx.outputs.iter().enumerate() {
                        if sha256(out.script_pubkey.as_bytes()) != sh {
                            continue;
                        }
                        let op = OutPoint {
                            txid: tx.txid(),
                            vout: vout as u32,
                        };
                        if mempool_spent.contains(&op) {
                            continue;
                        }
                        rows.push(json!({
                            "tx_hash": tx.txid().to_string(),
                            "tx_pos": vout,
                            "height": 0,
                            "value": out.value,
                        }));
                    }
                }
                reply(id, json!(rows))
            })
        }
        "blockchain.transaction.get" => {
            let Some(txid) = arr.first().and_then(Value::as_str).map(parse_txid) else {
                return reply_err(id, 1, "missing txid");
            };
            chain_value(queries, id, move |cs, mgr, id: Value| {
                let id = &id;
                if let Some(tx) = mgr.mempool().get(&txid) {
                    return reply(id, json!(hex::encode(&tx.encode())));
                }
                match cs.find_transaction(&txid).and_then(|bh| cs.body(&bh)) {
                    Some(block) => match block.transactions.iter().find(|t| t.txid() == txid) {
                        Some(tx) => reply(id, json!(hex::encode(&tx.encode()))),
                        None => reply_err(id, 2, "transaction not found"),
                    },
                    None => reply_err(id, 2, "transaction not found"),
                }
            })
        }
        "blockchain.transaction.get_merkle" => {
            let Some(txid) = arr.first().and_then(Value::as_str).map(parse_txid) else {
                return reply_err(id, 1, "missing txid");
            };
            let Some(height) = arr.get(1).and_then(Value::as_u64) else {
                return reply_err(id, 1, "missing height");
            };
            chain_value(queries, id, move |cs, _mgr, id: Value| {
                let id = &id;
                // The caller supplies the containing height — the block
                // itself locates the tx (no txindex needed).
                let Some(block) = cs.chain().get(height as usize).and_then(|bh| cs.body(bh)) else {
                    return reply_err(id, 1, "block not found");
                };
                let Some(pos) = block.transactions.iter().position(|t| t.txid() == txid) else {
                    return reply_err(id, 1, "transaction not in that block");
                };
                // Merkle branch: hash of the tx up to the root — the
                // standard SPV path.
                let txids: Vec<Txid> = block.transactions.iter().map(|t| t.txid()).collect();
                let branch = merkle_branch(&txids, pos);
                reply(
                    id,
                    json!({
                        "block_height": height,
                        "merkle": branch.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
                        "pos": pos,
                    }),
                )
            })
        }
        "blockchain.transaction.broadcast" => {
            let Some(raw) = arr.first().and_then(Value::as_str) else {
                return reply_err(id, 1, "missing tx hex");
            };
            // Reuse the node RPC's admission path — identical checks.
            let Ok(snap) = status.read().map(|s| s.clone()) else {
                return reply_err(id, -1, "node status unavailable");
            };
            let (result, error) = crate::rpc::dispatch(
                "sendrawtransaction",
                &json!([raw]),
                &snap,
                Some(queries),
                None,
                None,
                None,
                None,
            );
            match error {
                Some((code, msg)) => reply_err(id, code, &msg),
                None => reply(id, result),
            }
        }
        "blockchain.estimatefee" => {
            let target = arr.first().and_then(Value::as_u64).unwrap_or(1);
            let Ok(snap) = status.read().map(|s| s.clone()) else {
                return reply(id, json!(-1));
            };
            let (result, error) = crate::rpc::dispatch(
                "estimatesmartfee",
                &json!([target]),
                &snap,
                Some(queries),
                None,
                None,
                None,
                None,
            );
            match error {
                Some(_) => reply(id, json!(-1)),
                None => reply(id, result.get("feerate").cloned().unwrap_or(json!(-1))),
            }
        }
        "blockchain.relayfee" => chain_value(queries, id, |_cs, mgr, id: Value| {
            let id = &id;
            reply(id, json!(mgr.mempool().min_relay_fee() as f64 / 1e8))
        }),
        "mempool.get_fee_histogram" => chain_value(queries, id, |_cs, mgr, id: Value| {
            let id = &id;
            // (feerate, cumulative vsize) pairs, sorted by feerate desc —
            // the electrs/electrumx histogram shape.
            let entries: Vec<(i64, u64)> = mgr
                .mempool()
                .txids()
                .iter()
                .filter_map(|t| mgr.mempool().entry(t).map(|e| (e.fee, e.vsize as u64)))
                .collect();
            let mut pairs: Vec<(f64, u64)> = entries
                .into_iter()
                .map(|(fee, vsize)| (fee as f64 / vsize.max(1) as f64, vsize))
                .collect();
            pairs.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            let mut hist: Vec<Value> = Vec::new();
            let mut cur_rate: Option<f64> = None;
            let mut cur_size: u64 = 0;
            for (rate, size) in pairs {
                match cur_rate {
                    Some(r) if (r - rate).abs() < f64::EPSILON => cur_size += size,
                    _ => {
                        if let Some(r) = cur_rate {
                            hist.push(json!([r, cur_size]));
                        }
                        cur_rate = Some(rate);
                        cur_size = size;
                    }
                }
            }
            if let Some(r) = cur_rate {
                hist.push(json!([r, cur_size]));
            }
            reply(id, json!(hist))
        }),
        _ => reply_err(id, -32601, "method not found"),
    }
}

/// Runs `f` on the sync loop's chainstate and returns its `Value`
/// — the reply value the caller sends to the client.
fn chain_value(
    queries: &QuerySender,
    id: &Value,
    f: impl FnOnce(&mut Chainstate, &mut PeerManager<TcpStream>, Value) -> Value + Send + 'static,
) -> Value {
    let owned = id.clone();
    let (query, reply_rx) = crate::rpc::ChainQuery::new(move |cs, mgr| Ok(f(cs, mgr, owned)));
    if queries.send(query).is_err() {
        return reply_err(id, -1, "chain queries unavailable");
    }
    match reply_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(v)) => v,
        Ok(Err((code, msg))) => reply_err(id, code, &msg),
        Err(_) => reply_err(id, -1, "chain query timed out"),
    }
}

/// Parses a scripthash from its wire hex form. Like a tx/block hash,
/// the protocol carries `sha256(scriptPubKey)` byte-reversed in hex
/// (protocol-basics.html#script-hashes) — reverse back to the raw
/// digest order every internal comparison uses (see [`format_scripthash`]
/// for the inverse).
fn parse_scripthash(s: &str) -> Option<[u8; 32]> {
    let mut b = hex::decode(s).ok()?;
    if b.len() != 32 {
        return None;
    }
    b.reverse();
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Some(a)
}

/// Formats a raw-order scripthash for the wire — the inverse of
/// [`parse_scripthash`].
fn format_scripthash(sh: &[u8; 32]) -> String {
    let mut reversed = *sh;
    reversed.reverse();
    hex::encode(&reversed)
}

/// The SPV merkle branch for `txids[pos]` — sibling hashes leafward
/// to rootward (electrum's `merkle` array order).
fn merkle_branch(txids: &[Txid], pos: usize) -> Vec<Txid> {
    let mut branch = Vec::new();
    let mut level: Vec<Txid> = txids.to_vec();
    let mut idx = pos;
    while level.len() > 1 {
        if level.len() % 2 == 1
            && let Some(last) = level.last().copied()
        {
            level.push(last);
        }
        let sibling = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        branch.push(level[sibling]);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut cat = Vec::with_capacity(64);
            cat.extend_from_slice(pair[0].as_bytes());
            cat.extend_from_slice(pair[1].as_bytes());
            next.push(Txid::from_bytes(avila_consensus::hash::sha256d(&cat)));
        }
        level = next;
        idx /= 2;
    }
    branch
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::sync::SyncProgress;
    use avila_consensus::block::Block;
    use avila_consensus::check::SEQUENCE_FINAL;
    use avila_consensus::header::BlockHeader;
    use avila_consensus::params::Network;
    use avila_consensus::pow;
    use avila_consensus::script;
    use avila_consensus::transaction::Script;
    use avila_consensus::transaction::{OutPoint, TxIn, TxOut, Witness};
    use std::sync::RwLock;

    fn cb(height: u32) -> Transaction {
        let mut script_sig = script::push_int(i64::from(height));
        script_sig.push(script::OP_1);
        Transaction {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::NULL,
                script_sig: Script::new(script_sig),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![TxOut {
                value: 5_000_000_000,
                script_pubkey: Script::new(vec![0x51]),
            }],
            lock_time: 0,
        }
    }

    fn block_on(
        parent: &BlockHeader,
        txs: Vec<Transaction>,
        params: &avila_consensus::params::Params,
    ) -> Block {
        let mut block = Block {
            header: BlockHeader {
                version: 4,
                prev_block_hash: parent.hash(),
                merkle_root: parent.merkle_root,
                time: parent.time + 1,
                bits: params.pow_limit_compact(),
                nonce: 0,
            },
            transactions: txs,
        };
        let (root, _) = block.merkle_root();
        block.header.merkle_root = root;
        while pow::check_proof_of_work(&block.block_hash(), block.header.bits, params).is_err() {
            block.header.nonce += 1;
        }
        block
    }

    /// A live Electrum session against a real socket: subscribe,
    /// history, balance and a headers notification on connect.
    #[test]
    fn electrum_serves_and_notifies() {
        let params = Network::Regtest.params();
        let mut cs = Chainstate::new(&params);
        cs.enable_scripthashindex(None).unwrap();
        let b1 = block_on(&params.genesis_header, vec![cb(1)], &params);
        cs.accept_block(&b1, 1_700_000_000).unwrap();
        let spk_sh = sha256(&[0x51]);

        // The query-drain loop — what the sync loop does each tick.
        let (qtx, qrx) = mpsc::channel::<crate::rpc::ChainQuery>();
        let waiters = Arc::new(BlockWaiters::new());
        let waiters2 = waiters.clone();
        let mut mgr = PeerManager::new(4);
        let mut rescans = std::collections::VecDeque::new();
        thread::spawn(move || {
            loop {
                match qrx.recv_timeout(Duration::from_millis(50)) {
                    Ok(q) => q.answer(&mut cs, &mut mgr, &mut rescans),
                    Err(mpsc::RecvTimeoutError::Timeout) => waiters2.notify(&cs, mgr.mempool()),
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        let status: SharedStatus = Arc::new(RwLock::new(SyncProgress {
            peers: 0,
            connected_height: 1,
            header_height: 1,
            in_flight: 0,
            established_total: 0,
            disconnects: 0,
            recent: Vec::new(),
            peer_details: Vec::new(),
            mempool: (0, 0, None),
            elapsed_secs: 0,
        }));
        let cancel = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (qtx2, waiters3, status2, cancel2) =
            (qtx.clone(), waiters.clone(), status.clone(), cancel.clone());
        thread::spawn(move || {
            while !cancel2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((s, _)) => {
                        let q = qtx2.clone();
                        let w = waiters3.clone();
                        let st = status2.clone();
                        let c = cancel2.clone();
                        thread::spawn(move || handle(s, q, w, st, c));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        let conn = TcpStream::connect(addr).unwrap();
        let mut wr = conn.try_clone().unwrap();
        let mut send = |v: Value| {
            wr.write_all(format!("{}\n", serde_json::to_string(&v).unwrap()).as_bytes())
                .unwrap();
        };
        let mut rd = BufReader::new(conn);
        let read = |rd: &mut BufReader<TcpStream>| -> Value {
            let mut line = String::new();
            rd.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        };

        send(json!({"jsonrpc":"2.0","id":1,"method":"server.version","params":["t","1.4"]}));
        let r = read(&mut rd);
        assert!(r["result"].is_array());

        send(
            json!({"jsonrpc":"2.0","id":2,"method":"blockchain.scripthash.get_history","params":[format_scripthash(&spk_sh)]}),
        );
        let r = read(&mut rd);
        let hist = r["result"].as_array().unwrap();
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0]["height"], 1);

        send(
            json!({"jsonrpc":"2.0","id":3,"method":"blockchain.scripthash.get_balance","params":[format_scripthash(&spk_sh)]}),
        );
        let r = read(&mut rd);
        assert_eq!(r["result"]["confirmed"], 5_000_000_000i64, "reply: {r}");

        send(json!({"jsonrpc":"2.0","id":4,"method":"blockchain.headers.subscribe","params":[]}));
        let r = read(&mut rd);
        assert_eq!(r["result"]["height"], 1);

        cancel.store(true, Ordering::Relaxed);
    }

    /// A mempool tx paying a subscribed script must fire the
    /// subscription without waiting for a block — the check sees the
    /// pool, not just the chainstate.
    #[test]
    fn mempool_tx_fires_scripthash_subscription() {
        let params = Network::Regtest.params();
        let mut cs = Chainstate::new(&params);
        cs.enable_scripthashindex(None).unwrap();
        let b1 = block_on(&params.genesis_header, vec![cb(1)], &params);
        cs.accept_block(&b1, 1_700_000_000).unwrap();
        // Mature the spend source — 100-block coinbase maturity.
        let mut parent = b1.header;
        for h in 2..=101u32 {
            let b = block_on(&parent, vec![cb(h)], &params);
            cs.accept_block(&b, 1_700_000_000 + h).unwrap();
            parent = b.header;
        }
        let (qtx, qrx) = mpsc::channel::<crate::rpc::ChainQuery>();
        let waiters = Arc::new(BlockWaiters::new());
        let waiters2 = waiters.clone();
        let mut mgr = PeerManager::new(4);
        let mut rescans = std::collections::VecDeque::new();
        thread::spawn(move || {
            loop {
                match qrx.recv_timeout(Duration::from_millis(50)) {
                    Ok(q) => q.answer(&mut cs, &mut mgr, &mut rescans),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        waiters2.notify(&cs, mgr.mempool());
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        let status: SharedStatus = Arc::new(RwLock::new(SyncProgress {
            peers: 0,
            connected_height: 1,
            header_height: 1,
            in_flight: 0,
            established_total: 0,
            disconnects: 0,
            recent: Vec::new(),
            peer_details: Vec::new(),
            mempool: (0, 0, None),
            elapsed_secs: 0,
        }));
        let cancel = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (qtx2, waiters3, status2, cancel2) =
            (qtx.clone(), waiters.clone(), status.clone(), cancel.clone());
        thread::spawn(move || {
            while !cancel2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((s, _)) => {
                        let q = qtx2.clone();
                        let w = waiters3.clone();
                        let st = status2.clone();
                        let c = cancel2.clone();
                        thread::spawn(move || handle(s, q, w, st, c));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        let conn = TcpStream::connect(addr).unwrap();
        let mut wr = conn.try_clone().unwrap();
        let mut send = |v: Value| {
            wr.write_all(format!("{}\n", serde_json::to_string(&v).unwrap()).as_bytes())
                .unwrap();
        };
        let mut rd = BufReader::new(conn);
        rd.get_ref()
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let read = |rd: &mut BufReader<TcpStream>| -> Value {
            let mut line = String::new();
            rd.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        };

        // Subscribe to a fresh script — no history yet.
        let watch_spk = vec![0x51u8, 0x02];
        let watch_sh = sha256(&watch_spk);
        send(
            json!({"jsonrpc":"2.0","id":1,"method":"blockchain.scripthash.subscribe","params":[format_scripthash(&watch_sh)]}),
        );
        let r = read(&mut rd);
        assert!(r["result"].is_null(), "fresh script: {r}");

        // Inject a mempool tx paying it — through the query channel so
        // the pool mutation lands inside the notify loop's mgr.
        let mtx = Transaction {
            version: 2,
            inputs: vec![avila_consensus::transaction::TxIn {
                previous_output: OutPoint {
                    txid: b1.transactions[0].txid(),
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![avila_consensus::transaction::TxOut {
                value: 1_000,
                script_pubkey: Script::new(watch_spk.clone()),
            }],
            lock_time: 0,
        };
        let (q, rx2) = crate::rpc::ChainQuery::new(move |cs, mgr| {
            // The fixture spends an OP_TRUE coinbase — nonstandard, as
            // under Core, so opt out like `-acceptnonstdtxn=1`.
            mgr.mempool().set_require_standard(false);
            mgr.mempool()
                .accept_tx(mtx, cs, 1_700_000_100)
                .unwrap_or_else(|e| panic!("mature coinbase spend must accept: {e:?}"));
            Ok(serde_json::json!(null))
        });
        qtx.send(q).unwrap();
        let _ = rx2.recv();

        // The next notify tick must flip the status and push.
        let mut got_push = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            if rd.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let m: Value = serde_json::from_str(&line).unwrap();
            if m["method"] == "blockchain.scripthash.subscribe" {
                assert!(m["params"][1].is_string(), "push: {m}");
                // The pushed scripthash must echo back in the same
                // reversed wire form the client subscribed with.
                assert_eq!(
                    m["params"][0],
                    json!(format_scripthash(&watch_sh)),
                    "push: {m}"
                );
                got_push = true;
                break;
            }
        }
        assert!(got_push, "mempool tx must fire the subscription");
        cancel.store(true, Ordering::Relaxed);
    }

    /// The Electrum protocol doc's own worked example: the P2PKH
    /// script for `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` has scripthash
    /// `8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161`
    /// (protocol-basics.html#script-hashes) — `sha256(scriptPubKey)`
    /// with the bytes reversed for the wire, exactly like a tx hash.
    #[test]
    fn scripthash_matches_protocol_spec_example() {
        let params = Network::Mainnet.params();
        let script = avila_consensus::address::address_to_script(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            &params,
        )
        .unwrap();
        let raw = sha256(script.as_bytes());
        let wire = "8b01df4e368ea28f8dc0423bcf7a4923e3a12d307c875e47a0cfbf90b5c39161";
        assert_eq!(format_scripthash(&raw), wire);
        assert_eq!(parse_scripthash(wire), Some(raw));
    }

    fn empty_status() -> SharedStatus {
        Arc::new(RwLock::new(SyncProgress {
            peers: 0,
            connected_height: 0,
            header_height: 0,
            in_flight: 0,
            established_total: 0,
            disconnects: 0,
            recent: Vec::new(),
            peer_details: Vec::new(),
            mempool: (0, 0, None),
            elapsed_secs: 0,
        }))
    }

    /// A client that never sends a newline must not be able to grow
    /// the connection's line buffer without bound — past
    /// `MAX_LINE_LEN` the server disconnects rather than keep reading.
    #[test]
    fn oversized_line_disconnects() {
        let (qtx, _qrx) = mpsc::channel::<crate::rpc::ChainQuery>();
        let waiters = Arc::new(BlockWaiters::new());
        let status = empty_status();
        let cancel = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (qtx2, waiters2, status2, cancel2) =
            (qtx.clone(), waiters.clone(), status.clone(), cancel.clone());
        thread::spawn(move || {
            while !cancel2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((s, _)) => {
                        let q = qtx2.clone();
                        let w = waiters2.clone();
                        let st = status2.clone();
                        let c = cancel2.clone();
                        thread::spawn(move || handle(s, q, w, st, c));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        let mut conn = TcpStream::connect(addr).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        // One line, never terminated by `\n` — well past MAX_LINE_LEN.
        conn.write_all(&vec![b'a'; MAX_LINE_LEN + 4096]).unwrap();
        let mut buf = [0u8; 1];
        let n = conn.read(&mut buf).unwrap_or(0);
        assert_eq!(n, 0, "server must disconnect an oversized line");
        cancel.store(true, Ordering::Relaxed);
    }

    /// The accept loop must not spawn unbounded per-connection thread
    /// pairs — past `MAX_CONNECTIONS` a new socket is dropped outright
    /// rather than served.
    #[test]
    fn accept_loop_enforces_connection_cap() {
        let (qtx, _qrx) = mpsc::channel::<crate::rpc::ChainQuery>();
        let waiters = Arc::new(BlockWaiters::new());
        let status = empty_status();
        let cancel = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let cancel2 = cancel.clone();
        thread::spawn(move || accept_loop(listener, qtx, waiters, status, cancel2));

        // Open MAX_CONNECTIONS + a few more — every one past the cap
        // must be closed immediately (a read on it hits EOF) instead
        // of served.
        let mut conns: Vec<TcpStream> = (0..MAX_CONNECTIONS + 4)
            .map(|_| TcpStream::connect(addr).unwrap())
            .collect();
        thread::sleep(Duration::from_millis(500));

        let mut accepted = 0;
        let mut rejected = 0;
        for conn in &mut conns {
            conn.set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let mut buf = [0u8; 1];
            match conn.read(&mut buf) {
                Ok(0) => rejected += 1,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    accepted += 1;
                }
                other => panic!("unexpected read result: {other:?}"),
            }
        }
        cancel.store(true, Ordering::Relaxed);
        assert_eq!(rejected, 4, "accepted={accepted} rejected={rejected}");
        assert_eq!(accepted, MAX_CONNECTIONS);
    }

    /// A registration the node-wide waiter cap turns away must not
    /// leave the subscription dark — the cell falls back to polling.
    #[test]
    fn reregister_falls_back_to_polling_when_waiters_are_full() {
        let waiters = Arc::new(BlockWaiters::new());
        let (dummy_tx, _dummy_rx) = mpsc::sync_channel::<()>(1);
        for _ in 0..256 {
            assert!(waiters.register(Box::new(|_cs, _mp| false), dummy_tx.clone()));
        }
        assert!(
            !waiters.register(Box::new(|_cs, _mp| false), dummy_tx.clone()),
            "the cap (256) must already be full"
        );

        let (wake_tx, _wake_rx) = mpsc::sync_channel::<()>(1);
        let script_cell = Arc::new(Mutex::new(SubCell {
            confirmed_status: None,
            dirty: false,
            polling: false,
        }));
        reregister_script([7u8; 32], &script_cell, &waiters, wake_tx.clone());
        assert!(
            script_cell.lock().unwrap().polling,
            "a full cap must flip the script cell to polling"
        );

        let headers_cell = Arc::new(Mutex::new(SubCell {
            confirmed_status: None,
            dirty: false,
            polling: false,
        }));
        reregister_headers(&headers_cell, &waiters, wake_tx);
        assert!(
            headers_cell.lock().unwrap().polling,
            "a full cap must flip the headers cell to polling"
        );
    }

    /// End-to-end: even with the node-wide waiter cap exhausted, a
    /// scripthash subscription must still see a mempool payment — the
    /// pump's own polling fallback stands in for the missing waiter.
    #[test]
    fn scripthash_subscription_polls_when_waiter_cap_is_full() {
        let params = Network::Regtest.params();
        let mut cs = Chainstate::new(&params);
        cs.enable_scripthashindex(None).unwrap();
        let b1 = block_on(&params.genesis_header, vec![cb(1)], &params);
        cs.accept_block(&b1, 1_700_000_000).unwrap();
        let mut parent = b1.header;
        for h in 2..=101u32 {
            let b = block_on(&parent, vec![cb(h)], &params);
            cs.accept_block(&b, 1_700_000_000 + h).unwrap();
            parent = b.header;
        }

        let waiters = Arc::new(BlockWaiters::new());
        // Exhaust the node-wide cap (MAX_BLOCK_WAITERS = 256, rpc.rs)
        // with waiters that never fire, so this subscription's own
        // registration is guaranteed to be turned away.
        let (dummy_tx, _dummy_rx) = mpsc::sync_channel::<()>(1);
        for _ in 0..256 {
            assert!(waiters.register(Box::new(|_cs, _mp| false), dummy_tx.clone()));
        }

        let (qtx, qrx) = mpsc::channel::<crate::rpc::ChainQuery>();
        let waiters2 = waiters.clone();
        let mut mgr = PeerManager::new(4);
        let mut rescans = std::collections::VecDeque::new();
        thread::spawn(move || {
            loop {
                match qrx.recv_timeout(Duration::from_millis(50)) {
                    Ok(q) => q.answer(&mut cs, &mut mgr, &mut rescans),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        waiters2.notify(&cs, mgr.mempool());
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        let status = empty_status();
        let cancel = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let (qtx2, waiters3, status2, cancel2) =
            (qtx.clone(), waiters.clone(), status.clone(), cancel.clone());
        thread::spawn(move || {
            while !cancel2.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((s, _)) => {
                        let q = qtx2.clone();
                        let w = waiters3.clone();
                        let st = status2.clone();
                        let c = cancel2.clone();
                        thread::spawn(move || handle(s, q, w, st, c));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        let conn = TcpStream::connect(addr).unwrap();
        let mut wr = conn.try_clone().unwrap();
        let mut send = |v: Value| {
            wr.write_all(format!("{}\n", serde_json::to_string(&v).unwrap()).as_bytes())
                .unwrap();
        };
        let mut rd = BufReader::new(conn);
        rd.get_ref()
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let read = |rd: &mut BufReader<TcpStream>| -> Value {
            let mut line = String::new();
            rd.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        };

        let watch_spk = vec![0x51u8, 0x03];
        let watch_sh = sha256(&watch_spk);
        send(
            json!({"jsonrpc":"2.0","id":1,"method":"blockchain.scripthash.subscribe","params":[format_scripthash(&watch_sh)]}),
        );
        let r = read(&mut rd);
        assert!(r["result"].is_null(), "fresh script: {r}");

        let mtx = Transaction {
            version: 2,
            inputs: vec![avila_consensus::transaction::TxIn {
                previous_output: OutPoint {
                    txid: b1.transactions[0].txid(),
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: SEQUENCE_FINAL,
                witness: Witness::default(),
            }],
            outputs: vec![avila_consensus::transaction::TxOut {
                value: 1_000,
                script_pubkey: Script::new(watch_spk.clone()),
            }],
            lock_time: 0,
        };
        let (q, rx2) = crate::rpc::ChainQuery::new(move |cs, mgr| {
            // The fixture spends an OP_TRUE coinbase — nonstandard, as
            // under Core, so opt out like `-acceptnonstdtxn=1`.
            mgr.mempool().set_require_standard(false);
            mgr.mempool()
                .accept_tx(mtx, cs, 1_700_000_100)
                .unwrap_or_else(|e| panic!("mature coinbase spend must accept: {e:?}"));
            Ok(serde_json::json!(null))
        });
        qtx.send(q).unwrap();
        let _ = rx2.recv();

        let mut got_push = false;
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            if rd.read_line(&mut line).unwrap_or(0) == 0 {
                break;
            }
            let m: Value = serde_json::from_str(&line).unwrap();
            if m["method"] == "blockchain.scripthash.subscribe" {
                assert!(m["params"][1].is_string(), "push: {m}");
                got_push = true;
                break;
            }
        }
        assert!(
            got_push,
            "a full waiter cap must not silence the subscription"
        );
        cancel.store(true, Ordering::Relaxed);
    }
}

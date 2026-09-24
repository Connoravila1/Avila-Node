//! Stratum V2 Template Provider — the node's role in the Sv2 stack.
//!
//! Solo miners pair a Job Declarator/proxy against this socket; the
//! node pushes `NewTemplate`/`SetNewPrevHash` on tip changes and
//! answers `RequestTransactionData`/`SubmitSolution`. Pool-side
//! protocols (Mining, Job Declaration) stay out of scope — see
//! `docs/STRATUM_V2.md`.
//!
//! Framing is plaintext Sv2: a 6-byte header
//! `[extension u16 LE][msg_type u8][msg_len u24 LE]` followed by the
//! payload. Noise `NX` encryption is a follow-up — plaintext is legal
//! for loopback solo mining.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use avila_consensus::block::Block;
use avila_consensus::encode::write_var_bytes;
use avila_consensus::hash::BlockHash;
use avila_consensus::header::BlockHeader;
use avila_consensus::hex;
use avila_consensus::transaction::{Transaction, TxOut};

use crate::rpc::QuerySender;

// Template Distribution message types (spec 07).
const MSG_SETUP_CONNECTION: u8 = 0x00;
const MSG_SETUP_SUCCESS: u8 = 0x01;
const MSG_SETUP_ERROR: u8 = 0x03;
const MSG_COINBASE_OUTPUT_CONSTRAINTS: u8 = 0x70;
const MSG_NEW_TEMPLATE: u8 = 0x71;
const MSG_SET_NEW_PREV_HASH: u8 = 0x72;
const MSG_REQUEST_TRANSACTION_DATA: u8 = 0x73;
const MSG_REQUEST_TX_DATA_SUCCESS: u8 = 0x74;
const MSG_REQUEST_TX_DATA_ERROR: u8 = 0x75;
const MSG_SUBMIT_SOLUTION: u8 = 0x76;

/// Highest Sv2 version this TP speaks.
const MAX_VERSION: u16 = 2;

/// Hard cap on concurrent Sv2 connections — a loopback template
/// channel serves a handful of local proxies at most; past this the
/// listener drops new sockets rather than spawning unbounded threads.
const MAX_CONNECTIONS: usize = 16;

/// A connection that hasn't completed `SetupConnection` within this
/// window is dropped. Only a per-`read` timeout bounded any single
/// read; nothing bounded the connection's lifetime, so an unauthenticated
/// peer that stays silent (or trickles bytes) could hold a thread —
/// and a slot under [`MAX_CONNECTIONS`] — open indefinitely.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Set to `1` to let [`serve`] bind a non-loopback address. Plaintext
/// Sv2 framing (no Noise `NX` yet, see the module doc) is only safe on
/// loopback; this is an explicit, operator-chosen override for anyone
/// who has already put something else (a VPN, an SSH tunnel) in front.
const ALLOW_NONLOOPBACK_ENV: &str = "AVILA_SV2_ALLOW_NONLOOPBACK";

/// A served template — everything needed to rebuild the block from a
/// `SubmitSolution` coinbase.
struct ServedTemplate {
    /// Non-coinbase transactions in block order.
    txs: Vec<Transaction>,
    /// The template's prev-block hash (internal byte order).
    prev_hash: [u8; 32],
    /// nBits the header must carry.
    bits: u32,
}

/// Writes one framed message.
fn send(stream: &mut TcpStream, msg_type: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut hdr = [0u8; 6];
    // extension_type: channel bit unset, encryption bit unset.
    hdr[2] = msg_type;
    let n = payload.len() as u32;
    hdr[3..6].copy_from_slice(&n.to_le_bytes()[..3]);
    stream.write_all(&hdr)?;
    stream.write_all(payload)
}

fn le32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?))
}
fn le64(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// Serializes `outs` as concatenated `CTxOut`s — `value` (i64 LE) then
/// the scriptPubKey as a CompactSize length prefix plus bytes — the
/// plain Bitcoin encoding `NewTemplate.coinbase_tx_outputs` carries
/// (sv2-spec, Template Distribution, `NewTemplate`). A raw one-byte
/// length instead of CompactSize would silently truncate/corrupt the
/// framing for any script of 253 bytes or more.
fn encode_tp_outputs(outs: &[TxOut]) -> Vec<u8> {
    let mut buf = Vec::new();
    for out in outs {
        buf.extend_from_slice(&out.value.to_le_bytes());
        write_var_bytes(&mut buf, out.script_pubkey.as_bytes());
    }
    buf
}

/// The coinbase's merkle path — sibling hashes from leaf to root.
fn merkle_path(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut path = Vec::new();
    let mut idx = 0usize;
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level[level.len() - 1];
            level.push(last);
        }
        let sib = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        path.push(level[sib]);
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&pair[0]);
            buf.extend_from_slice(&pair[1]);
            next.push(avila_consensus::hash::sha256d(&buf));
        }
        level = next;
        idx /= 2;
    }
    path
}

/// Serves the Sv2 TP protocol on `addr`. Plaintext framing; refuses to
/// bind a non-loopback address unless `ALLOW_NONLOOPBACK_ENV` opts
/// in, since plaintext is only legal for loopback until Noise lands
/// (see the module doc).
///
/// # Errors
/// `io::Error` if the listener cannot bind, or (`PermissionDenied`) if
/// `addr` isn't loopback and the opt-in isn't set.
pub fn serve(
    addr: SocketAddr,
    queries: QuerySender,
    cancel: Arc<AtomicBool>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let allow_nonloopback = std::env::var(ALLOW_NONLOOPBACK_ENV).as_deref() == Ok("1");
    if refuses_bind(&addr, allow_nonloopback) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "sv2: refusing to bind non-loopback {addr} — plaintext framing has no Noise \
                 encryption yet; set {ALLOW_NONLOOPBACK_ENV}=1 to override"
            ),
        ));
    }
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        accept_loop(listener, queries, cancel);
    }))
}

/// Whether [`serve`] should refuse to bind `addr` — split out as a
/// pure function so the opt-in decision is unit-testable without
/// mutating the process environment (`std::env::set_var` requires
/// `unsafe` and touches every thread's env, so `serve` itself reads
/// the flag but this function decides).
fn refuses_bind(addr: &SocketAddr, allow_nonloopback: bool) -> bool {
    !addr.ip().is_loopback() && !allow_nonloopback
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
fn accept_loop(listener: TcpListener, queries: QuerySender, cancel: Arc<AtomicBool>) {
    let conns = Arc::new(AtomicUsize::new(0));
    while !cancel.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                if conns.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                    // Over the cap — drop the socket rather than spawn
                    // another unbounded thread.
                    drop(stream);
                    continue;
                }
                conns.fetch_add(1, Ordering::Relaxed);
                let queries = queries.clone();
                let cancel = cancel.clone();
                let slot = Slot(conns.clone());
                thread::spawn(move || {
                    let _slot = slot;
                    handle(stream, queries, cancel);
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn handle(stream: TcpStream, queries: QuerySender, cancel: Arc<AtomicBool>) {
    handle_with_timeout(stream, queries, cancel, HANDSHAKE_TIMEOUT);
}

/// [`handle`]'s body, with the handshake deadline as a parameter so
/// tests can exercise it without a real 10-second wait.
fn handle_with_timeout(
    mut stream: TcpStream,
    queries: QuerySender,
    cancel: Arc<AtomicBool>,
    handshake_timeout: Duration,
) {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let mut templates: HashMap<u64, ServedTemplate> = HashMap::new();
    let mut next_id: u64 = 1;
    let mut subscribed = false;
    let mut setup_done = false;
    let handshake_deadline = Instant::now() + handshake_timeout;
    let mut last_tip = [0u8; 32];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        if !setup_done && Instant::now() > handshake_deadline {
            // Never completed SetupConnection — drop it rather than
            // hold the thread (and its MAX_CONNECTIONS slot) open on
            // an unauthenticated peer indefinitely.
            return;
        }
        let mut hdr = [0u8; 6];
        match stream.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Idle window — after subscription, push new work on
                // every tip change (spec: SetNewPrevHash on a new best
                // block MUST follow immediately).
                if subscribed {
                    let (q, rx) = crate::rpc::ChainQuery::new(move |cs, _| {
                        Ok(serde_json::json!(hex::encode(cs.tip_hash().as_bytes())))
                    });
                    if queries.send(q).is_ok()
                        && let Ok(Ok(v)) = rx.recv_timeout(Duration::from_secs(5))
                        && let Some(t) = v
                            .as_str()
                            .and_then(|s| hex::decode(s).ok())
                            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                        && t != last_tip
                    {
                        last_tip = t;
                        push_templates(&mut stream, &queries, &mut templates, &mut next_id);
                    }
                }
                continue;
            }
            Err(_) => return,
        }
        let msg_type = hdr[2];
        let len = u32::from_le_bytes([hdr[3], hdr[4], hdr[5], 0]) as usize;
        if len > 2 * 1024 * 1024 {
            return;
        }
        let mut payload = vec![0u8; len];
        if stream.read_exact(&mut payload).is_err() {
            return;
        }
        match msg_type {
            MSG_SETUP_CONNECTION => {
                // protocol u8, min u16, max u16, flags u32, strings…
                if payload.len() < 9 {
                    return;
                }
                let min_v = u16::from_le_bytes([payload[1], payload[2]]);
                let max_v = u16::from_le_bytes([payload[3], payload[4]]);
                if max_v < min_v || MAX_VERSION < min_v {
                    let _ = send(
                        &mut stream,
                        MSG_SETUP_ERROR,
                        b"unsupported-protocol-version",
                    );
                    return;
                }
                let mut p = Vec::with_capacity(6);
                p.extend_from_slice(&max_v.min(MAX_VERSION).to_le_bytes());
                p.extend_from_slice(&0u32.to_le_bytes());
                if send(&mut stream, MSG_SETUP_SUCCESS, &p).is_err() {
                    return;
                }
                setup_done = true;
            }
            MSG_COINBASE_OUTPUT_CONSTRAINTS => {
                if payload.len() < 6 {
                    return;
                }
                // Spec: the server MUST immediately reply with its
                // current best template.
                subscribed = push_templates(&mut stream, &queries, &mut templates, &mut next_id);
                let (q, rx) = crate::rpc::ChainQuery::new(move |cs, _| {
                    Ok(serde_json::json!(hex::encode(cs.tip_hash().as_bytes())))
                });
                if queries.send(q).is_ok()
                    && let Ok(Ok(v)) = rx.recv_timeout(Duration::from_secs(5))
                    && let Some(t) = v
                        .as_str()
                        .and_then(|s| hex::decode(s).ok())
                        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                {
                    last_tip = t;
                }
            }
            MSG_REQUEST_TRANSACTION_DATA => {
                let Some(id) = le64(&payload, 0) else { return };
                let Some(t) = templates.get(&id) else {
                    let mut p = Vec::with_capacity(27);
                    p.extend_from_slice(&id.to_le_bytes());
                    p.extend_from_slice(b"unknown-template-id".as_slice());
                    let _ = send(&mut stream, MSG_REQUEST_TX_DATA_ERROR, &p);
                    continue;
                };
                // SEQ_64K[B0_64K] — u16 count + len-prefixed txs.
                let mut p = Vec::with_capacity(4096);
                p.extend_from_slice(&id.to_le_bytes());
                p.extend_from_slice(&(t.txs.len() as u16).to_le_bytes());
                for tx in &t.txs {
                    let raw = tx.encode();
                    p.extend_from_slice(&(raw.len() as u16).to_le_bytes());
                    p.extend_from_slice(&raw);
                }
                if send(&mut stream, MSG_REQUEST_TX_DATA_SUCCESS, &p).is_err() {
                    return;
                }
            }
            MSG_SUBMIT_SOLUTION => {
                // template_id u64, version u32, time u32, nonce u32,
                // coinbase_tx B0_64K.
                let (Some(id), Some(version), Some(time), Some(nonce)) = (
                    le64(&payload, 0),
                    le32(&payload, 8),
                    le32(&payload, 12),
                    le32(&payload, 16),
                ) else {
                    return;
                };
                let Some(cb_len) = payload
                    .get(20..22)
                    .map(|b| u16::from_le_bytes(b.try_into().unwrap_or([0, 0])))
                else {
                    return;
                };
                let Some(cb_bytes) = payload.get(22..22 + cb_len as usize) else {
                    return;
                };
                let Some(t) = templates.get(&id) else {
                    continue;
                };
                let Ok(coinbase) = Transaction::decode(cb_bytes) else {
                    continue;
                };
                let mut block = Block {
                    header: BlockHeader {
                        version: version as i32,
                        prev_block_hash: BlockHash::from_bytes(t.prev_hash),
                        merkle_root: avila_consensus::hash::MerkleRoot::from_bytes([0; 32]),
                        time,
                        bits: avila_consensus::arith::CompactTarget(t.bits),
                        nonce,
                    },
                    transactions: std::iter::once(coinbase)
                        .chain(t.txs.iter().cloned())
                        .collect(),
                };
                let (root, _mut) = block.merkle_root();
                block.header.merkle_root = root;
                let (q, rx) = crate::rpc::ChainQuery::new(move |cs, mgr| {
                    let now = crate::time::time() as u32;
                    match cs.accept_block(&block, now) {
                        Ok(avila_consensus::chainstate::Acceptance::Connected {
                            height,
                            reorged,
                            ..
                        }) => {
                            mgr.mempool().on_block_connected(&block, height);
                            if reorged {
                                let gone = cs.take_disconnected();
                                mgr.mempool().refill_from_disconnected(
                                    &gone,
                                    cs,
                                    now,
                                    true,
                                    usize::MAX,
                                );
                            }
                            mgr.announce_tip(cs);
                            Ok(serde_json::json!("accepted"))
                        }
                        other => Ok(serde_json::json!(format!("{other:?}"))),
                    }
                });
                if queries.send(q).is_ok() {
                    let _ = rx.recv_timeout(Duration::from_secs(30));
                }
            }
            _ => {}
        }
    }
}

/// Builds a fresh template via the sync loop and pushes
/// `NewTemplate` (future flag set — the client mines it after the
/// matching SetNewPrevHash) + `SetNewPrevHash`. Returns whether the
/// push succeeded.
fn push_templates(
    stream: &mut TcpStream,
    queries: &QuerySender,
    templates: &mut HashMap<u64, ServedTemplate>,
    next_id: &mut u64,
) -> bool {
    let id = *next_id;
    let (q, rx) = crate::rpc::ChainQuery::new(move |cs, mgr| {
        let now = crate::time::time() as u32;
        // The TP-side coinbase carries only the witness commitment —
        // build against a zero-value OP_TRUE slot so the whole
        // subsidy+fees lands in `coinbase_tx_value_remaining`.
        let t = mgr
            .mempool_ref()
            .build_template(
                cs,
                avila_consensus::transaction::Script::new(vec![0x51]),
                now,
            )
            .map_err(|e| (-1, format!("template: {e}")))?;
        let coinbase = &t.block.transactions[0];
        let txids: Vec<[u8; 32]> = t
            .block
            .transactions
            .iter()
            .map(|tx| tx.txid().to_bytes())
            .collect();
        let path = merkle_path(&txids);
        let subsidy_plus_fees = (t.fees.max(0) as u64)
            + avila_consensus::connect::block_subsidy(t.height, cs.tree().params()).max(0) as u64;

        // --- NewTemplate payload ---
        // TP-side outputs = the witness commitment (BIP141's last
        // output) — output[0] is our zero-value OP_TRUE build slot,
        // which must NOT be handed to the client (it already claims
        // subsidy+fees in `value_remaining`).
        let tp_outs = &coinbase.outputs[1.min(coinbase.outputs.len())..];
        let tp_outputs = encode_tp_outputs(tp_outs);
        let mut nt = Vec::with_capacity(256);
        nt.extend_from_slice(&id.to_le_bytes());
        nt.push(1); // future_template
        nt.extend_from_slice(&t.block.header.version.to_le_bytes());
        nt.extend_from_slice(&coinbase.version.to_le_bytes());
        let cb_sig = coinbase.inputs[0].script_sig.as_bytes();
        let prefix_len = cb_sig.len().min(8) as u8;
        nt.push(prefix_len);
        nt.extend_from_slice(&cb_sig[..prefix_len as usize]);
        nt.extend_from_slice(&coinbase.inputs[0].sequence.to_le_bytes());
        nt.extend_from_slice(&subsidy_plus_fees.to_le_bytes());
        nt.extend_from_slice(&(tp_outs.len() as u32).to_le_bytes());
        nt.extend_from_slice(&(tp_outputs.len() as u16).to_le_bytes());
        nt.extend_from_slice(&tp_outputs);
        nt.extend_from_slice(&coinbase.lock_time.to_le_bytes());
        nt.push(path.len() as u8);
        for h in &path {
            nt.extend_from_slice(h);
        }

        // --- SetNewPrevHash payload ---
        let mut snp = Vec::with_capacity(76);
        snp.extend_from_slice(&id.to_le_bytes());
        snp.extend_from_slice(t.block.header.prev_block_hash.as_bytes());
        snp.extend_from_slice(&t.block.header.time.to_le_bytes());
        snp.extend_from_slice(&t.block.header.bits.0.to_le_bytes());
        let expanded = t.block.header.bits.expand();
        snp.extend_from_slice(&expanded.value.to_le_bytes());

        Ok(serde_json::json!({
            "nt": hex::encode(&nt),
            "snp": hex::encode(&snp),
            "prev": hex::encode(t.block.header.prev_block_hash.as_bytes()),
            "bits": t.block.header.bits.0,
            "txs": t.block.transactions[1..].iter()
                .map(|tx| hex::encode(&tx.encode()))
                .collect::<Vec<_>>(),
        }))
    });
    if queries.send(q).is_err() {
        return false;
    }
    let Ok(Ok(v)) = rx.recv_timeout(Duration::from_secs(10)) else {
        return false;
    };
    let (Some(nt), Some(snp), Some(prev)) = (
        v["nt"].as_str().and_then(|s| hex::decode(s).ok()),
        v["snp"].as_str().and_then(|s| hex::decode(s).ok()),
        v["prev"].as_str().and_then(|s| hex::decode(s).ok()),
    ) else {
        return false;
    };
    let txs: Vec<Transaction> = v["txs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .filter_map(|s| hex::decode(s).ok())
                .filter_map(|b| Transaction::decode(&b).ok())
                .collect()
        })
        .unwrap_or_default();
    let mut prev_hash = [0u8; 32];
    if prev.len() == 32 {
        prev_hash.copy_from_slice(&prev);
    }
    templates.insert(
        id,
        ServedTemplate {
            txs,
            prev_hash,
            bits: v["bits"].as_u64().unwrap_or(0) as u32,
        },
    );
    *next_id += 1;
    send(stream, MSG_NEW_TEMPLATE, &nt).is_ok() && send(stream, MSG_SET_NEW_PREV_HASH, &snp).is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use avila_consensus::transaction::Script;

    /// The Sv2 spec's `NewTemplate.coinbase_tx_outputs` is plain
    /// Bitcoin `CTxOut` serialization: a script of 253 bytes or more
    /// must switch to the `0xfd` CompactSize prefix, not wrap a raw
    /// byte length.
    #[test]
    fn encode_tp_outputs_uses_compact_size_for_long_scripts() {
        let long_script = vec![0xabu8; 300];
        let outs = vec![TxOut {
            value: 12_345,
            script_pubkey: Script::new(long_script.clone()),
        }];
        let buf = encode_tp_outputs(&outs);
        // value (8) + CompactSize prefix (0xfd + u16 LE = 3 bytes) + script (300).
        assert_eq!(buf.len(), 8 + 3 + 300);
        assert_eq!(&buf[0..8], &12_345i64.to_le_bytes());
        assert_eq!(
            buf[8], 0xfd,
            "a 300-byte script needs the 0xfd CompactSize prefix"
        );
        assert_eq!(u16::from_le_bytes([buf[9], buf[10]]), 300);
        assert_eq!(&buf[11..], &long_script[..]);
    }

    /// The common case (a short script) still uses the single-byte
    /// CompactSize form — no regression there.
    #[test]
    fn encode_tp_outputs_uses_single_byte_for_short_scripts() {
        let script = vec![0x51u8; 5];
        let outs = vec![TxOut {
            value: 1,
            script_pubkey: Script::new(script.clone()),
        }];
        let buf = encode_tp_outputs(&outs);
        assert_eq!(buf.len(), 8 + 1 + 5);
        assert_eq!(buf[8], 5);
        assert_eq!(&buf[9..], &script[..]);
    }

    #[test]
    fn refuses_bind_requires_loopback_or_opt_in() {
        let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let remote: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert!(!refuses_bind(&loopback, false));
        assert!(refuses_bind(&remote, false));
        assert!(!refuses_bind(&remote, true), "the opt-in must allow it");
    }

    /// `serve` itself must refuse a non-loopback address by default —
    /// the module comment's "loopback-only until Noise lands" rule,
    /// enforced rather than just documented.
    #[test]
    fn serve_refuses_nonloopback_by_default() {
        let (qtx, _qrx) = std::sync::mpsc::channel::<crate::rpc::ChainQuery>();
        let cancel = Arc::new(AtomicBool::new(false));
        let remote: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let err = serve(remote, qtx.clone(), cancel.clone()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        // The default (loopback) case must still work.
        let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let handle = serve(loopback, qtx, cancel.clone()).unwrap();
        cancel.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    /// The accept loop must not spawn unbounded per-connection
    /// threads — past `MAX_CONNECTIONS` a new socket is dropped
    /// outright rather than served.
    #[test]
    fn accept_loop_enforces_connection_cap() {
        let (qtx, _qrx) = std::sync::mpsc::channel::<crate::rpc::ChainQuery>();
        let cancel = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let cancel2 = cancel.clone();
        thread::spawn(move || accept_loop(listener, qtx, cancel2));

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

    /// A connection that never completes `SetupConnection` must not
    /// hold its thread (and a `MAX_CONNECTIONS` slot) open forever —
    /// past the handshake deadline it's dropped.
    #[test]
    fn handshake_deadline_drops_silent_connections() {
        let (qtx, _qrx) = std::sync::mpsc::channel::<crate::rpc::ChainQuery>();
        let cancel = Arc::new(AtomicBool::new(false));
        // A blocking listener — exactly one connection is expected, so
        // there's no need for accept_loop's nonblocking poll here.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (q, c) = (qtx, cancel.clone());
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_with_timeout(stream, q, c, Duration::from_millis(150));
        });

        let mut conn = TcpStream::connect(addr).unwrap();
        conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        // Say nothing — never send SetupConnection.
        let mut buf = [0u8; 1];
        let n = conn.read(&mut buf).unwrap_or(0);
        assert_eq!(
            n, 0,
            "a silent connection must be dropped once the handshake deadline passes"
        );
        cancel.store(true, Ordering::Relaxed);
    }
}

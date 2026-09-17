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
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use avila_consensus::block::Block;
use avila_consensus::hash::BlockHash;
use avila_consensus::header::BlockHeader;
use avila_consensus::hex;
use avila_consensus::transaction::Transaction;

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

/// Serves the Sv2 TP protocol on `addr`. Plaintext framing; bind
/// loopback-only unless Noise lands.
pub fn serve(
    addr: SocketAddr,
    queries: QuerySender,
    cancel: Arc<AtomicBool>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    Ok(thread::spawn(move || {
        while !cancel.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let queries = queries.clone();
                    let cancel = cancel.clone();
                    thread::spawn(move || handle(stream, queries, cancel));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    }))
}

fn handle(mut stream: TcpStream, queries: QuerySender, cancel: Arc<AtomicBool>) {
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    let mut templates: HashMap<u64, ServedTemplate> = HashMap::new();
    let mut next_id: u64 = 1;
    let mut subscribed = false;
    let mut last_tip = [0u8; 32];
    loop {
        if cancel.load(Ordering::Relaxed) {
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
                            height, ..
                        }) => {
                            mgr.mempool().on_block_connected(&block, height);
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
        let mut tp_outputs = Vec::new();
        for out in tp_outs {
            // CTxOut serialization: value i64 + compactSize scriptlen + script.
            tp_outputs.extend_from_slice(&out.value.to_le_bytes());
            tp_outputs.push(out.script_pubkey.as_bytes().len() as u8);
            tp_outputs.extend_from_slice(out.script_pubkey.as_bytes());
        }
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

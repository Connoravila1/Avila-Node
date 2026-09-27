// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Gate 4 — corpus-wide occurrence-record join over a REAL mainnet window.
//!
//! Consumes an `AVCORP03` corpus (from `tools/ibd_corpus_window.py`) —
//! block records carry the raw 80-byte header, so hash/parent linkage,
//! merkle commitments, block time, PoW self-consistency and every
//! context-free transaction rule are checked, not assumed.
//!
//! Resolution uses THE SAME shared join (`examples/shared/join_engine.rs`)
//! that the `state_join` fixture oracle tests byte-for-byte against
//! `connect_block`:
//!
//!   CREATED/SPENT ledgers → join_window(created, spends, boundary)
//!   boundary = resolved pre-window sources, seeded once per outpoint
//!
//! One `known_invalid` decision drives exit status AND export: ANY
//! detected invalidity (header/hash/linkage/PoW/merkle/context-free,
//! join violations, predicate violations, script failures) → exit 1 in
//! BOTH modes and no state artifact is published. Unresolved inputs are
//! a coverage class — strict mode exits 1 on them; `--diagnostic` emits
//! an explicitly labeled incomplete projection (still refused on known
//! invalidity). Materialization applies the valid prefix only.
//!
//! Scope labels: starting-state completeness is false here (the corpus
//! boundary carries only spend-mentioned coins); retarget correctness,
//! BIP34 height commitment, and pre-window ancestry (MTP before the
//! segment's first block, assume-valid/script-skip boundary) are not
//! verifiable from a bare window. Everything the corpus bytes support is
//! checked.

use avila_consensus::block::Block;
use avila_consensus::chain::{HeaderTree, InsertStatus};
use avila_consensus::check::{
    BlockContext, MAX_BLOCK_SIGOPS_COST, MAX_MONEY, check_block, contextual_check_block,
    is_final_tx,
};
use avila_consensus::connect::{
    COINBASE_MATURITY, Coin, bip68_locks_satisfied, block_subsidy, tx_sigop_cost,
};
use avila_consensus::hash::{BlockHash, sha256};
use avila_consensus::header::BlockHeader;
use avila_consensus::params::Network;
use avila_consensus::script::{ScriptFlags, block_script_flags};
use avila_consensus::sigchecker::check_input_scripts;
use avila_consensus::snapverify::{self, for_each_coin};
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxOut};
use std::collections::HashMap;

#[path = "shared/join_engine.rs"]
mod join_engine;
use join_engine::{
    BoundaryView, Creation, FlatBoundary, FlatBuilder, JoinRes, Occ, Spend, build_boundary,
    join_window,
};

#[derive(Clone)]
struct Source {
    out: TxOut,
    creation_height: u32,
    coinbase: bool,
}

struct BlockRec {
    height: u32,
    hash: BlockHash,
    header: BlockHeader,
    txs: Vec<TxRec>,
}

struct TxRec {
    tx: Transaction,
    srcs: Vec<Option<Source>>,
    is_cb: bool,
}

fn u32at(b: &[u8], o: &mut usize) -> u32 {
    let v = u32::from_le_bytes(b[*o..*o + 4].try_into().unwrap());
    *o += 4;
    v
}

fn parse_corpus(raw: &[u8]) -> Vec<BlockRec> {
    assert_eq!(&raw[..8], b"AVCORP03", "bad magic (need AVCORP03)");
    let mut o = 8usize;
    let mut blocks = Vec::new();
    while o < raw.len() {
        let height = u32at(raw, &mut o);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&raw[o..o + 32]);
        o += 32;
        let header = BlockHeader::decode(&raw[o..o + 80]).expect("header decodes");
        o += 80;
        let hash = BlockHash::from_bytes(hash_bytes);
        // the stored hash must be the header's real hash
        assert_eq!(header.hash(), hash, "header/hash mismatch @{height}");
        let n_tx = u32at(raw, &mut o) as usize;
        let mut txs = Vec::with_capacity(n_tx);
        for _ in 0..n_tx {
            let n = u32at(raw, &mut o) as usize;
            assert!(o + n <= raw.len());
            let tx = Transaction::decode(&raw[o..o + n]).expect("corpus tx decodes");
            o += n;
            let n_in = u32at(raw, &mut o) as usize;
            let mut srcs = Vec::with_capacity(n_in);
            for _ in 0..n_in {
                let resolved = raw[o];
                o += 1;
                if resolved == 0 {
                    srcs.push(None);
                } else {
                    let value = i64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
                    o += 8;
                    let sl = u32at(raw, &mut o) as usize;
                    let spk = Script::new(raw[o..o + sl].to_vec());
                    o += sl;
                    let creation_height = u32at(raw, &mut o);
                    let coinbase = raw[o] & 1 != 0;
                    o += 1;
                    srcs.push(Some(Source {
                        out: TxOut {
                            value,
                            script_pubkey: spk,
                        },
                        creation_height,
                        coinbase,
                    }));
                }
            }
            assert_eq!(srcs.len(), tx.inputs.len());
            let is_cb = tx.inputs.len() == 1 && tx.inputs[0].previous_output.is_null();
            txs.push(TxRec { tx, srcs, is_cb });
        }
        blocks.push(BlockRec {
            height,
            hash,
            header,
            txs,
        });
    }
    blocks
}

fn rss_hwm_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .map(|kb: u64| kb * 1024)
        .unwrap_or(0)
}

/// Serializes one `(outpoint, coin)` record in canonical form.
fn put_coin_stream(
    w: &mut impl std::io::Write,
    st: &mut snapverify::ShaState,
    txid: &[u8; 32],
    vout: u32,
    value: i64,
    code: u32,
    spk: &[u8],
) -> std::io::Result<()> {
    let mut emit = |b: &[u8]| -> std::io::Result<()> {
        w.write_all(b)?;
        st.update(b);
        Ok(())
    };
    emit(txid)?;
    emit(&vout.to_le_bytes())?;
    emit(&value.to_le_bytes())?;
    emit(&(spk.len() as u32).to_le_bytes())?;
    emit(spk)?;
    emit(&(code >> 1).to_le_bytes())?;
    emit(&[(code & 1) as u8])?;
    Ok(())
}

/// Streamed canonical export for the flat live set: boundary alive
/// records are already in `(txid, vout)` order; `extra` (in-window
/// creations) is sorted then merged — byte-identical output to the old
/// whole-buffer path with zero large intermediate allocations.
fn stream_canonical_flat(
    out_path: &str,
    boundary: &FlatBoundary,
    extra: &HashMap<OutPoint, Coin>,
) -> std::io::Result<(u64, [u8; 32])> {
    let mut ex: Vec<(&OutPoint, &Coin)> = extra.iter().collect();
    ex.sort_unstable_by_key(|(op, _)| (op.txid, op.vout));
    let mut ex_i = 0usize;
    let mut st = snapverify::ShaState::default();
    let mut bytes = 0u64;
    let mut w = std::io::BufWriter::with_capacity(1 << 22, std::fs::File::create(out_path)?);
    for i in boundary.alive_indices() {
        let (txid, vout, value, code, spk) = boundary.record_raw(i);
        // Emit every `extra` record sorting strictly before this one.
        while ex_i < ex.len() && (*ex[ex_i].0.txid.as_bytes(), ex[ex_i].0.vout) < (txid, vout) {
            let (op, coin) = ex[ex_i];
            let c = u64::from(coin.height) << 1 | u64::from(coin.coinbase);
            let spk = coin.out.script_pubkey.as_bytes();
            put_coin_stream(
                &mut w,
                &mut st,
                op.txid.as_bytes(),
                op.vout,
                coin.out.value,
                u32::try_from(c).expect("coin code fits u32"),
                spk,
            )?;
            bytes += 53 + spk.len() as u64;
            ex_i += 1;
        }
        put_coin_stream(&mut w, &mut st, &txid, vout, value, code, spk)?;
        bytes += 53 + spk.len() as u64;
    }
    while ex_i < ex.len() {
        let (op, coin) = ex[ex_i];
        let c = u64::from(coin.height) << 1 | u64::from(coin.coinbase);
        let spk = coin.out.script_pubkey.as_bytes();
        put_coin_stream(
            &mut w,
            &mut st,
            op.txid.as_bytes(),
            op.vout,
            coin.out.value,
            u32::try_from(c).expect("coin code fits u32"),
            spk,
        )?;
        bytes += 53 + spk.len() as u64;
        ex_i += 1;
    }
    use std::io::Write as _;
    w.flush()?;
    w.get_ref().sync_all()?;
    Ok((bytes, st.finalize()))
}

fn money_range(v: i64) -> bool {
    (0..=MAX_MONEY).contains(&v)
}

fn jstr(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Streaming single-SHA256 of a file — identical to `sha256sum`, no
/// whole-file allocation (boundaries run to multiple GB).
fn file_sha256(p: &str) -> Option<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).ok()?;
    let mut st = avila_consensus::snapverify::ShaState::default();
    let mut chunk = vec![0u8; 8 << 20];
    loop {
        let n = f.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        st.update(&chunk[..n]);
    }
    Some(avila_consensus::hex::encode(&st.finalize()))
}

fn hexid(h: &BlockHash) -> String {
    h.as_bytes()
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn main() {
    let wall_t = std::time::Instant::now();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = match args.first() {
        Some(p) if !p.starts_with("--") => p.clone(),
        _ => {
            eprintln!(
                "usage: window_join <corpus.bin> [--workers N] [--diagnostic] [--segment lo:hi] [--params mainnet|regtest] [--manifest PATH] [--export PATH]"
            );
            std::process::exit(2);
        }
    };
    let opt = |n: &str| -> Option<String> {
        args.iter()
            .position(|a| a == n)
            .and_then(|i| args.get(i + 1).cloned())
    };
    let diagnostic = args.iter().any(|a| a == "--diagnostic");
    // `--require-complete` — the checked complete-run entry point: exit 0
    // only when EVERY applicable check ran and passed (all three donor
    // pins, header + block context, full coverage, zero unresolved).
    let require_complete = args.iter().any(|a| a == "--require-complete");
    let params = match opt("--params").as_deref() {
        None | Some("mainnet") => Network::Mainnet.params(),
        Some("regtest") => Network::Regtest.params(),
        Some(other) => {
            eprintln!("unknown --params {other}");
            std::process::exit(2);
        }
    };
    let segment: Option<(u32, u32)> = opt("--segment").map(|s| {
        let (lo, hi) = s.split_once(':').expect("--segment lo:hi");
        (lo.parse().unwrap(), hi.parse().unwrap())
    });
    let manifest_path = opt("--manifest");
    let boundary_path = opt("--boundary"); // dumptxoutset-format starting state
    let boundary_base_hash = opt("--boundary-base-hash"); // pin from dumptxoutset
    let boundary_base_height_pin = opt("--boundary-base-height");
    let boundary_txoutset_pin = opt("--boundary-txoutset-hash");
    let headers_path = opt("--headers"); // HCHAIN01 full header index (export_headers)
    let run_manifest_path = opt("--run-manifest");
    let export_path = opt("--export").unwrap_or_else(|| format!("{path}.canonical"));
    let workers: usize = opt("--workers")
        .unwrap_or_else(|| "4".into())
        .parse()
        .unwrap();
    if workers == 0 {
        eprintln!("error: --workers 0 runs no verification; refusing");
        std::process::exit(2);
    }

    // ---- stage: parse ------------------------------------------------
    let t = std::time::Instant::now();
    let raw = std::fs::read(&path).expect("corpus readable");
    let corpus_bytes = raw.len() as u64;
    let corpus_sha256 = avila_consensus::hex::encode(&sha256(&raw));
    let mut blocks = parse_corpus(&raw);
    drop(raw);
    if let Some((lo, hi)) = segment {
        blocks.retain(|b| (lo..=hi).contains(&b.height));
    }
    // Processing must follow the verified chain order — blk-file order is
    // not height order and later stages `break` on the first bad height.
    blocks.sort_by_key(|b| b.height);
    if blocks.is_empty() {
        eprintln!("fatal: no blocks selected (empty corpus or segment outside its coverage)");
        std::process::exit(2);
    }
    let parse_s = t.elapsed().as_secs_f64();
    // min/max — corpus order is blk-file order, not height order.
    let window_lo = blocks.iter().map(|b| b.height).min().unwrap();
    let window_hi = blocks.iter().map(|b| b.height).max().unwrap();
    let header_hash_verified = blocks.len(); // assert in parse enforced each

    // ---- coverage + header linkage manifest --------------------------
    let mut heights_seen: HashMap<u32, usize> = HashMap::new();
    for b in &blocks {
        *heights_seen.entry(b.height).or_insert(0) += 1;
    }
    let dup_heights = heights_seen.values().filter(|&&n| n > 1).count();
    let mut missing_heights = 0usize;
    let mut longest_run = 0usize;
    let mut run = 0usize;
    for h in window_lo..=window_hi {
        if heights_seen.contains_key(&h) {
            run += 1;
            longest_run = longest_run.max(run);
        } else {
            missing_heights += 1;
            run = 0;
        }
    }
    let present_heights: std::collections::HashSet<u32> = heights_seen.keys().copied().collect();
    let by_hash: HashMap<BlockHash, &BlockRec> = blocks.iter().map(|b| (b.hash, b)).collect();
    let by_height: HashMap<u32, &BlockRec> = blocks.iter().map(|b| (b.height, b)).collect();
    // linkage: each block whose (height-1) is present must name it as parent
    let mut linkage_checked = 0usize;
    let mut linkage_broken = 0usize;
    let mut first_link_break_h = 0u32;
    for b in &blocks {
        let Some(parent_h) = b.height.checked_sub(1) else {
            continue; // h=0 has no parent height
        };
        if present_heights.contains(&parent_h) {
            linkage_checked += 1;
            let parent_ok = by_hash
                .get(&b.header.prev_block_hash)
                .is_some_and(|p| p.height == parent_h);
            if !parent_ok {
                linkage_broken += 1;
                if first_link_break_h == 0 {
                    first_link_break_h = b.height;
                }
            }
        }
    }
    // MTP where ≥11 consecutive ancestors exist in-corpus
    // MTP of block at height h's parent chain: median of its 11 latest
    // ancestor times — only computable when all 11 are in the corpus.
    let mtp_of = |h: u32| -> Option<u32> {
        let mut times = Vec::with_capacity(11);
        let mut cur = *by_height.get(&h)?;
        loop {
            times.push(cur.header.time);
            if times.len() == 11 {
                break;
            }
            let prev = by_hash.get(&cur.header.prev_block_hash)?;
            if prev.height + 1 != cur.height {
                return None;
            }
            cur = prev;
        }
        times.sort_unstable();
        Some(times[5])
    };
    let mut mtp_computable = 0usize;
    let mut block_mtp: HashMap<u32, u32> = HashMap::new();
    for b in &blocks {
        let Some(parent_h) = b.height.checked_sub(1) else {
            continue; // h=0: no in-window parent
        };
        if let Some(m) = mtp_of(parent_h) {
            block_mtp.insert(b.height, m);
            mtp_computable += 1;
        }
    }
    if let Some(mp) = &manifest_path {
        let mut lines = String::new();
        for b in &blocks {
            lines += &format!(
                "{{\"height\":{},\"hash\":{},\"parent\":{},\"time\":{},\"mtp\":{}}}\n",
                b.height,
                jstr(&hexid(&b.hash)),
                jstr(&hexid(&b.header.prev_block_hash)),
                b.header.time,
                block_mtp
                    .get(&b.height)
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "null".into()),
            );
        }
        std::fs::write(mp, lines).expect("manifest writable");
    }

    // ---- production header context (--headers manifest) ---------------
    // HCHAIN01: u32 count | count × header80 | "CHAIN" | u32 | hashes —
    // emitted by `export_headers` from the node's own `state.dat` index.
    // Every manifest header is inserted through HeaderTree, which runs the
    // production AcceptBlockHeader + ContextualCheckBlockHeader checks per
    // header: PoW, required_bits retarget, median-time floor, future
    // ceiling, buried-version floors. The tree then supplies real parent
    // MTP and BIP68 ancestor lookups for the whole chain — not just the
    // window slice.
    let mut tree: Option<HeaderTree> = None;
    let mut chain: Option<Vec<[u8; 32]>> = None;
    let mut headers_loaded = 0usize;
    let mut headers_inserted = 0usize;
    let mut headers_height_mismatch = 0usize;
    let mut headers_chain_mismatch = 0usize;
    let mut headers_failed_selected = 0usize;
    let mut headers_missing_selected = 0usize;
    // (height, reason) for selected-chain header failures — applied to
    // first_bad once it exists.
    let mut header_bad: Vec<(u32, String)> = Vec::new();
    let mut headers_unknown_parent = 0usize;
    let mut headers_failed = 0usize;
    let mut window_headers_in_tree = 0usize;
    let mut headers_chain_missing = 0usize;
    let mut headers_s = 0f64;
    if let Some(hp) = &headers_path {
        let th = std::time::Instant::now();
        let data = std::fs::read(hp).expect("headers manifest readable");
        let need = |o: usize, n: usize| {
            if o + n > data.len() {
                eprintln!("fatal: headers manifest truncated at byte {o}");
                std::process::exit(2);
            }
            &data[o..o + n]
        };
        if need(0, 8) != b"HCHAIN01".as_slice() {
            eprintln!("fatal: headers manifest bad magic");
            std::process::exit(2);
        }
        let count = u32::from_le_bytes(need(8, 4).try_into().unwrap()) as usize;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let mut t = HeaderTree::new(params);
        // Selected-chain binding: a header failing production insert only
        // taints the window if a corpus block carries that hash — track
        // which hashes failed, don't treat unrelated index entries as
        // proof the selected chain is invalid.
        let mut failed_hashes: std::collections::HashSet<BlockHash> = Default::default();
        let mut unknown_hashes: std::collections::HashSet<BlockHash> = Default::default();
        for i in 0..count {
            let raw = need(12 + i * 80, 80);
            let hdr = BlockHeader::decode(raw).unwrap_or_else(|e| {
                eprintln!("fatal: headers manifest record {i} undecodable: {e}");
                std::process::exit(2);
            });
            match t.insert(&hdr, now) {
                Ok(InsertStatus::AlreadyKnown { .. }) => {}
                Ok(_) => headers_inserted += 1,
                Err(avila_consensus::chain::ChainError::UnknownParent(_)) => {
                    headers_unknown_parent += 1;
                    unknown_hashes.insert(hdr.hash());
                }
                Err(e) => {
                    headers_failed += 1;
                    failed_hashes.insert(hdr.hash());
                    if headers_failed <= 3 {
                        eprintln!("header {} insert failed: {e}", hdr.hash());
                    }
                }
            }
        }
        let tail = 12 + count * 80;
        if need(tail, 5) != b"CHAIN".as_slice() {
            eprintln!("fatal: headers manifest missing CHAIN section");
            std::process::exit(2);
        }
        let cc = u32::from_le_bytes(need(tail + 5, 4).try_into().unwrap()) as usize;
        // The best-chain hash list — index i is the hash at height i.
        let mut chain_hashes: Vec<[u8; 32]> = Vec::with_capacity(cc);
        for i in 0..cc {
            chain_hashes.push(need(tail + 9 + i * 32, 32).try_into().unwrap());
        }
        if headers_failed > 0 || headers_unknown_parent > 0 {
            eprintln!(
                "warning: {headers_failed} indexed headers fail production checks; \
{headers_unknown_parent} have unknown parents"
            );
        }
        headers_loaded = count;
        // Real parent MTP for every window block whose parent is indexed,
        // plus the selected-chain binding: the header node must exist AND
        // sit at the corpus-labeled height AND (when the chain list covers
        // it) be the best-chain hash at that height.
        for b in &blocks {
            if let Some(m) = t.median_time_past(&b.header.prev_block_hash) {
                block_mtp.insert(b.height, m);
            }
            match t.get(&b.hash) {
                Some(node) => {
                    window_headers_in_tree += 1;
                    if node.height != b.height {
                        headers_height_mismatch += 1;
                        header_bad.push((
                            b.height,
                            format!(
                                "corpus height {} ≠ chain height {} for {}",
                                b.height, node.height, b.hash
                            ),
                        ));
                    }
                }
                None => {
                    if failed_hashes.contains(&b.hash) {
                        headers_failed_selected += 1;
                        header_bad.push((
                            b.height,
                            format!("window header {} failed production insert", b.hash),
                        ));
                    } else if unknown_hashes.contains(&b.hash) {
                        headers_missing_selected += 1; // ancestry absent — context gap
                    } else {
                        headers_missing_selected += 1; // not indexed at all — context gap
                    }
                }
            }
            match chain_hashes.get(b.height as usize) {
                Some(h) if *h != *b.hash.as_bytes() => {
                    headers_chain_mismatch += 1;
                    header_bad.push((
                        b.height,
                        format!("CHAIN[{}] ≠ corpus hash {}", b.height, b.hash),
                    ));
                }
                // No chain entry at this height: the selected-chain
                // comparison cannot run → missing context, not invalid.
                None => headers_chain_missing += 1,
                _ => {}
            }
        }
        chain = Some(chain_hashes);
        tree = Some(t);
        headers_s = th.elapsed().as_secs_f64();
    }

    // ---- stage A: context-free block checks + ledger emit -------------
    let t = std::time::Instant::now();
    let mut first_bad_h = u32::MAX;
    let mut first_bad_msg = String::new();
    for (h, msg) in header_bad.drain(..) {
        if h < first_bad_h {
            first_bad_h = h;
            first_bad_msg = msg;
        }
    }
    let mark_bad = |h: u32, msg: String, first_bad_h: &mut u32, m: &mut String| {
        if h < *first_bad_h {
            *first_bad_h = h;
            *m = msg;
        }
    };
    if linkage_broken > 0 {
        mark_bad(
            first_link_break_h,
            "header linkage broken".into(),
            &mut first_bad_h,
            &mut first_bad_msg,
        );
    }
    let mut ctx_free_failed = 0usize;
    // Production `contextual_check_block` — finality for every tx
    // (incl. coinbase), BIP34 coinbase height, witness-commitment /
    // unexpected-witness rules, block weight. Requires a header tree:
    // without one there is no parent MTP, so the check is *unevaluated*
    // (incomplete), never silently skipped-as-pass.
    let mut ctx_block_evaluated = 0usize;
    let mut ctx_block_failed = 0usize;
    let mut ctx_block_unevaluated = 0usize;
    let mut created: Vec<Creation> = Vec::new();
    let mut spends: Vec<Spend> = Vec::new();
    let mut boundary_specs: Vec<(OutPoint, Coin)> = Vec::new();
    let mut n_txs = 0usize;
    let mut n_inputs_noncb = 0usize;
    let mut n_srcs_resolved = 0usize;
    let mut n_srcs_unresolved = 0usize;
    let mut gap_heights_sourced = 0usize;
    for b in &blocks {
        let block = Block {
            header: b.header,
            transactions: b.txs.iter().map(|t| t.tx.clone()).collect(),
        };
        if let Err(e) = check_block(&block, &params) {
            ctx_free_failed += 1;
            mark_bad(
                b.height,
                format!("check_block: {e:?}"),
                &mut first_bad_h,
                &mut first_bad_msg,
            );
        }
        if tree.is_some() {
            match block_mtp.get(&b.height) {
                Some(&mtp) => {
                    let bctx = BlockContext {
                        params: &params,
                        height: b.height,
                        parent_median_time_past: Some(mtp),
                    };
                    match contextual_check_block(&block, &bctx) {
                        Ok(()) => ctx_block_evaluated += 1,
                        Err(e) => {
                            ctx_block_failed += 1;
                            mark_bad(
                                b.height,
                                format!("contextual_check_block: {e:?}"),
                                &mut first_bad_h,
                                &mut first_bad_msg,
                            );
                        }
                    }
                }
                None => ctx_block_unevaluated += 1,
            }
        } else {
            ctx_block_unevaluated += 1;
        }
        for (j, tr) in b.txs.iter().enumerate() {
            n_txs += 1;
            let txid = tr.tx.txid();
            for (i, inp) in tr.tx.inputs.iter().enumerate() {
                if inp.previous_output.is_null() {
                    continue;
                }
                n_inputs_noncb += 1;
                match &tr.srcs[i] {
                    Some(s) => {
                        n_srcs_resolved += 1;
                        if s.creation_height < window_lo {
                            boundary_specs.push((
                                inp.previous_output,
                                Coin {
                                    out: s.out.clone(),
                                    height: s.creation_height,
                                    coinbase: s.coinbase,
                                },
                            ));
                        } else if !present_heights.contains(&s.creation_height) {
                            gap_heights_sourced += 1;
                        }
                    }
                    None => n_srcs_unresolved += 1,
                }
                spends.push(Spend {
                    pos: Occ {
                        h: b.height,
                        tx: j as u32,
                        idx: i as u32,
                    },
                    op: inp.previous_output,
                });
            }
            for (n, o) in tr.tx.outputs.iter().enumerate() {
                if o.script_pubkey.is_unspendable() {
                    continue;
                }
                created.push(Creation {
                    pos: Occ {
                        h: b.height,
                        tx: j as u32,
                        idx: n as u32,
                    },
                    op: OutPoint {
                        txid,
                        vout: n as u32,
                    },
                    coin: Coin {
                        out: o.clone(),
                        height: b.height,
                        coinbase: tr.is_cb,
                    },
                });
            }
        }
    }
    let emit_s = t.elapsed().as_secs_f64();

    // ---- stage B: SHARED partition → sort → merge-join -----------------
    // Boundary precedence: an explicitly supplied starting state
    // (--boundary, dumptxoutset format) is authoritative — corpus specs
    // become a CONSISTENCY CHECK against it (a spec that disagrees with
    // the supplied state marks the outpoint conflicted). Without it the
    // boundary is assembled from spend-mentioned specs only.
    let t = std::time::Instant::now();
    let mut boundary_loaded: Option<FlatBoundary> = None;
    let mut boundary_load_coins = 0usize;
    let mut boundary_dup_outpoints = 0usize;
    let mut boundary_base_height: Option<u32> = None;
    let mut boundary_load_s = 0f64;
    let mut boundary_base_hash_json = "null".to_string();
    let mut boundary_txoutset_hash_json = "null".to_string();
    if let Some(bp) = &boundary_path {
        // A supplied boundary is meaningful only as the state at the
        // window's parent block: the corpus's first block must name it
        // (the audit's comparison window starts "immediately after" the
        // exported boundary).
        let base_height = blocks[0].height.checked_sub(1).unwrap_or_else(|| {
            eprintln!("fatal: window starts at height 0 — no parent boundary can precede it");
            std::process::exit(2);
        });
        boundary_base_height = Some(base_height);
        if let Some(pin) = &boundary_base_height_pin {
            let pinned: u32 = pin.parse().expect("--boundary-base-height u32");
            if pinned != base_height {
                eprintln!(
                    "fatal: donor height {pinned} ≠ window parent height {base_height} — boundary is not adjacent"
                );
                std::process::exit(2);
            }
        }
        // Flat sorted table — pre-sized from the declared coin count so
        // neither the record vec nor the script blob ever re-allocates.
        let snap_path = std::path::Path::new(bp);
        let expected = snapverify::read_header(
            &std::fs::File::open(snap_path).expect("boundary readable for header"),
        )
        .map(|h| h.coins_count as usize)
        .unwrap_or(0);
        let mut fb = FlatBuilder::new(expected);
        let tb = std::time::Instant::now();
        let loaded = for_each_coin(
            snap_path,
            Some(base_height), // creation heights may not exceed the base
            |txid_b, vout, code, value, spk| {
                fb.push(txid_b, vout, value, code, spk);
                Ok(())
            },
        )
        .unwrap_or_else(|e| {
            eprintln!("fatal: --boundary load failed: {e}");
            std::process::exit(2);
        });
        let snap_hdr = loaded.header;
        let (flat, dups) = fb.finish();
        boundary_dup_outpoints = dups;
        if boundary_dup_outpoints > 0 {
            eprintln!("fatal: boundary contains {boundary_dup_outpoints} duplicate outpoints");
            std::process::exit(2);
        }
        boundary_load_s = tb.elapsed().as_secs_f64();
        boundary_load_coins = flat.txids_len();
        if snap_hdr.network != params.message_start {
            eprintln!(
                "fatal: boundary network {:02x?} ≠ params {:02x?}",
                snap_hdr.network, params.message_start
            );
            std::process::exit(2);
        }
        if let Some(pin) = &boundary_base_hash {
            // dumptxoutset reports display-order; file stores LE bytes
            let want = avila_consensus::hex::decode(pin)
                .ok()
                .filter(|v| v.len() == 32)
                .map(|mut v| {
                    v.reverse();
                    v
                })
                .unwrap_or_else(|| {
                    eprintln!("fatal: --boundary-base-hash is not 64-char hex");
                    std::process::exit(2);
                });
            if snap_hdr.base_blockhash != want[..] {
                eprintln!("fatal: --boundary base hash ≠ --boundary-base-hash pin");
                std::process::exit(2);
            }
        }
        if snap_hdr.base_blockhash[..] != blocks[0].header.prev_block_hash.as_bytes()[..] {
            eprintln!(
                "fatal: boundary base ≠ corpus window parent — window not adjacent to the exported state"
            );
            std::process::exit(2);
        }
        // Ancestry binding: the supplied CHAIN list must name the donor's
        // base hash at the donor's height — proving the window's parent
        // is a selected-chain block, not an unrelated index entry.
        if let Some(ch) = &chain {
            match ch.get(base_height as usize) {
                Some(h) if h[..] != snap_hdr.base_blockhash[..] => {
                    eprintln!(
                        "fatal: CHAIN[{}] ≠ boundary base hash — donor not on selected chain",
                        base_height
                    );
                    std::process::exit(2);
                }
                None => {
                    eprintln!(
                        "fatal: CHAIN list ({}) doesn't reach boundary base height {}",
                        ch.len(),
                        base_height
                    );
                    std::process::exit(2);
                }
                _ => {}
            }
        }
        // coin-set commitment: hash_serialized_3 over the loaded coins
        // must match the donor's published txoutset_hash (display order).
        let disp_commit: Vec<u8> = loaded.txoutset_hash.iter().rev().cloned().collect();
        boundary_txoutset_hash_json = jstr(&avila_consensus::hex::encode(&disp_commit));
        if let Some(pin) = &boundary_txoutset_pin {
            let want = avila_consensus::hex::decode(pin)
                .ok()
                .filter(|v| v.len() == 32)
                .map(|mut v| {
                    v.reverse(); // display hex → internal order
                    v
                })
                .unwrap_or_else(|| {
                    eprintln!("fatal: --boundary-txoutset-hash is not 64-char hex");
                    std::process::exit(2);
                });
            if *want != loaded.txoutset_hash {
                eprintln!("fatal: loaded coin-set commitment ≠ --boundary-txoutset-hash pin");
                std::process::exit(2);
            }
        }
        let disp: Vec<u8> = snap_hdr.base_blockhash.iter().rev().cloned().collect();
        boundary_base_hash_json = jstr(&avila_consensus::hex::encode(&disp));
        boundary_loaded = Some(flat);
    }
    let boundary_supplied = boundary_loaded.is_some();
    let (boundary, boundary_conflicts, conflict_ops) = if boundary_supplied {
        // specs vs supplied state: agreement is consistency-verified;
        // disagreement marks the outpoint conflicted (known invalidity).
        let loaded = boundary_loaded.take().unwrap();
        let mut conflict_ops: std::collections::HashSet<OutPoint> = Default::default();
        for (op, spec_coin) in &boundary_specs {
            match loaded.b_get(op) {
                Some(c) if c == *spec_coin => {}
                _ => {
                    conflict_ops.insert(*op);
                }
            }
        }
        let n_conflicts = conflict_ops.len();
        (loaded, n_conflicts, conflict_ops)
    } else {
        let (map, n_conflicts, ops) = build_boundary(boundary_specs.into_iter());
        let n = map.len();
        (FlatBoundary::from_map(map, n), n_conflicts, ops)
    };
    let report = join_window(&created, &spends, &boundary, &conflict_ops);
    let resolved = report.resolved;
    let join_s = t.elapsed().as_secs_f64();
    for (pos, _v) in &report.violations {
        if pos.h < first_bad_h {
            first_bad_h = pos.h;
            first_bad_msg = format!("BIP30 duplicate creation @ {pos:?}");
        }
    }
    for (pos, r) in &resolved {
        match r {
            JoinRes::DupSpend(_) if pos.h < first_bad_h => {
                first_bad_h = pos.h;
                first_bad_msg = format!("double spend @ {pos:?}");
            }
            JoinRes::BoundaryConflict if pos.h < first_bad_h => {
                first_bad_h = pos.h;
                first_bad_msg = format!("conflicting boundary spec @ {pos:?}");
            }
            _ => {}
        }
    }
    // Under a complete supplied state a `Missing` spend is a spend of a
    // coin that never existed — known invalidity, not a coverage gap.
    // `first_missing` gives the earliest such position (the diagnostics
    // the audit asked for); it folds into the same first-bad boundary.
    if boundary_supplied
        && let Some(mpos) = report.first_missing
        && mpos.h < first_bad_h
    {
        first_bad_h = mpos.h;
        first_bad_msg = format!("spend of absent coin @ {mpos:?} (complete boundary)");
    }

    // ---- stage C: predicates over resolved coins -----------------------
    let t = std::time::Instant::now();
    let bip113_active = |h: u32| h >= params.csv_height; // MTP-based finality
    let mut fully_resolved_txs = 0usize;
    let mut excluded_txs = 0usize;
    let mut exec_inputs = 0usize;
    let mut immature_violations = 0usize;
    let mut value_violations = 0usize;
    let mut nonfinal_violations = 0usize;
    let mut time_locks_unevaluated = 0usize;
    let mut sigop_violations = 0usize;
    let mut cb_bound_checks = 0usize;
    let mut cb_bound_violations = 0usize;
    let mut bip68_evaluated = 0usize;
    let mut bip68_violations = 0usize;
    let mut bip68_unevaluated = 0usize;
    let mut resolved_spec_unjoined = 0usize;
    let mut unresolved_spec_inputs = 0usize;
    let mut blocks_fully_covered = 0usize;
    let mut admitted: Vec<(u32, &Transaction, Vec<TxOut>, ScriptFlags)> = Vec::new();
    for b in &blocks {
        if b.height >= first_bad_h {
            break;
        }
        let mut block_fees = 0i64;
        let cb_flags = block_script_flags(&params, b.height, &b.hash);
        let mut block_sigops_total = tx_sigop_cost(&b.txs[0].tx, &[], cb_flags);
        let mut block_all_resolved = true;
        for (j, tr) in b.txs.iter().enumerate() {
            if tr.is_cb {
                continue;
            }
            let mut coins: Vec<Coin> = Vec::with_capacity(tr.tx.inputs.len());
            let mut complete = true;
            let mut bad_input = false;
            for (i, _inp) in tr.tx.inputs.iter().enumerate() {
                let pos = Occ {
                    h: b.height,
                    tx: j as u32,
                    idx: i as u32,
                };
                match resolved.get(&pos) {
                    Some(JoinRes::Coin(c)) => coins.push(c.clone()),
                    Some(JoinRes::DupSpend(_)) | Some(JoinRes::BoundaryConflict) => {
                        bad_input = true;
                        break;
                    }
                    _ => {
                        if tr.srcs[i].is_some() {
                            resolved_spec_unjoined += 1;
                        } else {
                            unresolved_spec_inputs += 1;
                        }
                        complete = false;
                        break;
                    }
                }
            }
            if bad_input {
                continue;
            }
            if !complete {
                excluded_txs += 1;
                block_all_resolved = false;
                continue;
            }
            fully_resolved_txs += 1;
            exec_inputs += coins.len();
            if coins
                .iter()
                .any(|c| c.coinbase && b.height.saturating_sub(c.height) < COINBASE_MATURITY)
            {
                immature_violations += 1;
                mark_bad(
                    b.height,
                    format!("immature coinbase @ tx{j}"),
                    &mut first_bad_h,
                    &mut first_bad_msg,
                );
                continue;
            }
            let mut vin: i64 = 0;
            let mut bad = false;
            for c in &coins {
                if !money_range(c.out.value) {
                    bad = true;
                    break;
                }
                vin = match vin.checked_add(c.out.value) {
                    Some(v) if money_range(v) => v,
                    _ => {
                        bad = true;
                        break;
                    }
                };
            }
            if !bad {
                let mut vout: i64 = 0;
                for o in &tr.tx.outputs {
                    vout = match vout.checked_add(o.value) {
                        Some(v) if money_range(v) => v,
                        _ => {
                            bad = true;
                            break;
                        }
                    };
                }
                if !bad && vout > vin {
                    bad = true;
                }
                if !bad {
                    let fee = vin - vout;
                    if !money_range(fee) {
                        bad = true;
                    } else {
                        block_fees = match block_fees.checked_add(fee) {
                            Some(f) if money_range(f) => f,
                            _ => {
                                bad = true;
                                0
                            }
                        };
                    }
                }
            }
            if bad {
                value_violations += 1;
                mark_bad(
                    b.height,
                    format!("value violation @ tx{j}"),
                    &mut first_bad_h,
                    &mut first_bad_msg,
                );
                continue;
            }
            // finality: height-form always evaluable; time-form uses the
            // era-correct cutoff — parent MTP post-BIP113, candidate block
            // time pre-BIP113 — counted unevaluated when not computable.
            if tr.tx.lock_time >= 500_000_000 {
                let cutoff = if bip113_active(b.height) {
                    block_mtp.get(&b.height).copied()
                } else {
                    Some(b.header.time)
                };
                match cutoff {
                    Some(cut) => {
                        if !is_final_tx(&tr.tx, b.height, cut) {
                            nonfinal_violations += 1;
                            mark_bad(
                                b.height,
                                format!("non-final @ tx{j}"),
                                &mut first_bad_h,
                                &mut first_bad_msg,
                            );
                            continue;
                        }
                    }
                    None => {
                        time_locks_unevaluated += 1; // admitted but not certified
                    }
                }
            } else if !is_final_tx(&tr.tx, b.height, b.header.time) {
                nonfinal_violations += 1;
                mark_bad(
                    b.height,
                    format!("non-final @ tx{j}"),
                    &mut first_bad_h,
                    &mut first_bad_msg,
                );
                continue;
            }
            let sigops = tx_sigop_cost(&tr.tx, &coins, cb_flags);
            block_sigops_total += sigops;
            if block_sigops_total > MAX_BLOCK_SIGOPS_COST {
                sigop_violations += 1;
                mark_bad(
                    b.height,
                    format!("sigops @ tx{j}"),
                    &mut first_bad_h,
                    &mut first_bad_msg,
                );
                continue;
            }
            // BIP68 relative sequence locks — the production check needs
            // the ancestor-carrying HeaderTree (--headers); without it the
            // input is counted unevaluated rather than assumed.
            if bip113_active(b.height) {
                match (&tree, block_mtp.get(&b.height).copied()) {
                    (Some(t), Some(pmtp)) => {
                        bip68_evaluated += 1;
                        if !bip68_locks_satisfied(
                            &tr.tx,
                            &coins,
                            b.height,
                            pmtp,
                            t,
                            &b.header.prev_block_hash,
                        ) {
                            bip68_violations += 1;
                            mark_bad(
                                b.height,
                                format!("bip68 unsatisfied @ tx{j}"),
                                &mut first_bad_h,
                                &mut first_bad_msg,
                            );
                            continue;
                        }
                    }
                    _ => {
                        bip68_unevaluated += 1;
                    }
                }
            }
            let outs: Vec<TxOut> = coins.iter().map(|c| c.out.clone()).collect();
            admitted.push((b.height, &tr.tx, outs, cb_flags));
        }
        if block_all_resolved {
            blocks_fully_covered += 1;
            cb_bound_checks += 1;
            let cb_sum: i64 = b.txs[0].tx.outputs.iter().map(|o| o.value).sum();
            if cb_sum > block_subsidy(b.height, &params).saturating_add(block_fees) {
                cb_bound_violations += 1;
                mark_bad(
                    b.height,
                    "coinbase overpay".into(),
                    &mut first_bad_h,
                    &mut first_bad_msg,
                );
            }
        }
    }
    let pred_s = t.elapsed().as_secs_f64();

    // ---- stage D: script verification bound to resolved coins ---------
    let t = std::time::Instant::now();
    let queued_tasks = admitted.len();
    let (completed_tasks, succeeded_inputs, inputs_in_failed_txs, failed_tasks);
    {
        use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
        let cursor = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let fails_tx = AtomicUsize::new(0);
        let fails_in = AtomicUsize::new(0);
        let ok_in = AtomicUsize::new(0);
        let earliest_fail = AtomicU32::new(u32::MAX);
        std::thread::scope(|s| {
            let mut hs = Vec::new();
            for _ in 0..workers {
                let cursor = &cursor;
                let done = &done;
                let fails_tx = &fails_tx;
                let fails_in = &fails_in;
                let ok_in = &ok_in;
                let earliest_fail = &earliest_fail;
                let admitted = &admitted;
                hs.push(s.spawn(move || {
                    loop {
                        let k = cursor.fetch_add(1, Ordering::Relaxed);
                        if k >= admitted.len() {
                            return;
                        }
                        let (bh, tx, outs, flags) = &admitted[k];
                        if check_input_scripts(tx, outs, *flags).is_err() {
                            fails_tx.fetch_add(1, Ordering::Relaxed);
                            fails_in.fetch_add(outs.len(), Ordering::Relaxed);
                            earliest_fail.fetch_min(*bh, Ordering::Relaxed);
                        } else {
                            ok_in.fetch_add(outs.len(), Ordering::Relaxed);
                        }
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }
            for h in hs {
                h.join().unwrap();
            }
        });
        completed_tasks = done.load(Ordering::Relaxed);
        succeeded_inputs = ok_in.load(Ordering::Relaxed);
        inputs_in_failed_txs = fails_in.load(Ordering::Relaxed);
        failed_tasks = fails_tx.load(Ordering::Relaxed);
        let ef = earliest_fail.load(Ordering::Relaxed);
        if ef != u32::MAX && ef < first_bad_h {
            first_bad_h = ef;
            first_bad_msg = format!("script verification failure @ {ef}");
        } else if failed_tasks > 0 && first_bad_msg.is_empty() {
            first_bad_msg = "script verification failure".into();
        }
    }
    let script_s = t.elapsed().as_secs_f64();

    // ---- ONE invalidity decision drives exit + export ------------------
    // With a complete supplied state, `Missing` is not a coverage gap:
    // a spend whose outpoint is absent from a COMPLETE boundary never
    // existed (or was spent before the window) — known invalidity.
    let missing_is_invalid = boundary_supplied;
    let known_invalid = first_bad_h != u32::MAX
        || !report.violations.is_empty()
        || report.dup_spends > 0
        || boundary_conflicts > 0
        || failed_tasks > 0
        || ctx_free_failed > 0
        || ctx_block_failed > 0
        || headers_failed_selected > 0
        || headers_height_mismatch > 0
        || headers_chain_mismatch > 0
        || linkage_broken > 0
        || (missing_is_invalid && report.missing_spends > 0);

    // ---- stage E: materialize valid-prefix survivor set ----------------
    let t = std::time::Instant::now();
    let boundary_coins_report = boundary.b_len();
    // Flat-boundary live set: boundary records carry an alive bitmap;
    // in-window creations live in `extra` and shadow boundary records
    // (a re-created boundary op kills the boundary bit, then the new
    // coin lives in `extra` — identical to HashMap insert-overwrite).
    let mut boundary = boundary;
    let mut extra: HashMap<OutPoint, Coin> = HashMap::new();
    let mut order: Vec<(Occ, bool, usize)> = Vec::new();
    for (k, c) in created.iter().enumerate() {
        order.push((c.pos, true, k));
    }
    for (k, s) in spends.iter().enumerate() {
        order.push((s.pos, false, k));
    }
    order.sort_by_key(|a| a.0);
    let mut applied_events = 0usize;
    for (pos, is_creation, k) in order {
        if pos.h >= first_bad_h {
            break;
        }
        if is_creation {
            let op = &created[k].op;
            if let Some(i) = boundary.find(op.txid.as_bytes(), op.vout) {
                boundary.kill(i);
            }
            extra.insert(*op, created[k].coin.clone());
        } else {
            let op = &spends[k].op;
            if extra.remove(op).is_none()
                && let Some(i) = boundary.find(op.txid.as_bytes(), op.vout)
            {
                boundary.kill(i);
            }
        }
        applied_events += 1;
    }
    let mat_s = t.elapsed().as_secs_f64();

    // ---- component completion (explicit, not one overloaded flag) ------
    // `resolved_inputs_complete` is driven by the JOIN (a spend resolved
    // from an authenticated local creation record needs no spec hint).
    let resolved_inputs_complete = report.missing_spends == 0;
    let script_jobs_complete = completed_tasks == queued_tasks && failed_tasks == 0;
    // Corpus boundary = spend-mentioned pre-window coins only; unspent
    // pre-window outputs are absent by construction → never "complete"
    // without an explicitly supplied full starting state.
    let starting_state_complete = boundary_supplied;
    let header_context_checked = linkage_broken == 0 && linkage_checked > 0;
    // `header_context_full` — every window header was verified in a
    // HeaderTree built from the node's own index (production
    // AcceptBlockHeader/ContextualCheckBlockHeader: PoW, required_bits,
    // MTP floor, version floors) AND sits at the corpus-labeled height on
    // the selected best chain. A failed or missing window header, a
    // height disagreement, or a CHAIN-entry disagreement all disqualify.
    let header_context_full = tree.is_some()
        && window_headers_in_tree == blocks.len()
        && headers_height_mismatch == 0
        && headers_chain_mismatch == 0
        && headers_failed_selected == 0
        && headers_missing_selected == 0;
    // `contextual_blocks_complete` — production `contextual_check_block`
    // evaluated on every block (BIP34 cb-height, witness rules, weight,
    // full-tx finality incl. coinbase). Without a header tree there is no
    // parent MTP → the check is unevaluated, not skipped-as-passed.
    let contextual_blocks_complete =
        tree.is_some() && ctx_block_evaluated == blocks.len() && ctx_block_unevaluated == 0;
    // All three donor pins supplied — a "complete" run must be anchored.
    let all_pins = boundary_base_height_pin.is_some()
        && boundary_base_hash.is_some()
        && boundary_txoutset_pin.is_some();
    let context_free_checks_complete = ctx_free_failed == 0;
    // Coverage must span the REQUESTED interval, endpoints included — a
    // window missing a requested boundary block is incomplete, not a
    // smaller valid window.
    let coverage_endpoints = match segment {
        Some((lo, hi)) => window_lo == lo && window_hi == hi,
        None => true,
    };
    let coverage_complete = missing_heights == 0 && dup_heights == 0 && coverage_endpoints;
    // `window_complete` — every component check that production requires
    // for this era actually ran and passed on every block: complete
    // authenticated starting state with ALL THREE pins, every spend
    // resolved, every script job executed, full header context AND
    // selected-chain binding, per-block contextual checks evaluated,
    // zero unevaluated locks, and every block's coinbase bound checked
    // (fully-covered blocks only can certify fees).
    let window_complete = !known_invalid
        && resolved_inputs_complete
        && script_jobs_complete
        && starting_state_complete
        && all_pins
        && header_context_full
        && contextual_blocks_complete
        && coverage_complete
        && headers_chain_missing == 0
        && time_locks_unevaluated == 0
        && bip68_unevaluated == 0
        && blocks_fully_covered == blocks.len();

    // ---- stage F: export — only when a state may legitimately exist ----
    // Never exported on known invalidity (either mode). In strict mode a
    // state artifact additionally requires full input coverage.
    let t = std::time::Instant::now();
    let mut exported = false;
    let may_publish =
        !known_invalid && (diagnostic || (resolved_inputs_complete && script_jobs_complete));
    if may_publish {
        // streamed write + inline digest — no multi-GB output buffer
        let (nbytes, digest) = stream_canonical_flat(&export_path, &boundary, &extra)
            .unwrap_or_else(|e| {
                eprintln!("fatal: export write failed: {e}");
                std::process::exit(2);
            });
        exported = true;
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        println!(
            "{{\"type\":\"export\",\"path\":{},\"bytes\":{},\"sha256\":{},\
\"chainstate_complete\":{},\"projection\":\"valid_prefix\"}}",
            jstr(&export_path),
            nbytes,
            jstr(&hex),
            window_complete
        );
    }
    let export_s = t.elapsed().as_secs_f64();
    let rss = rss_hwm_bytes();

    println!(
        "{{\"type\":\"window_join\",\"window\":[{},{}],\"corpus_bytes\":{},\
\"blocks_present\":{},\"heights_span\":{},\"heights_missing\":{},\
\"duplicate_heights\":{},\"longest_contiguous_run\":{},\
\"header_hash_verified\":{},\"linkage_checked\":{},\"linkage_broken\":{},\
\"mtp_computable\":{},\"context_free_failed\":{},\
\"txs\":{},\"inputs_noncb\":{},\
\"srcs_resolved\":{},\"srcs_unresolved\":{},\"gap_height_sourced\":{},\
\"spend_records\":{},\"creation_records\":{},\
\"boundary_coins\":{},\"boundary_conflicts\":{},\
\"join_dup_creations\":{},\"join_dup_spends\":{},\"join_missing_spends\":{},\
\"fully_resolved_txs\":{},\"excluded_txs\":{},\
\"resolved_spec_unjoined\":{},\"unresolved_spec_inputs\":{},\
\"blocks_fully_covered\":{},\
\"exec_inputs\":{},\"queued_tasks\":{},\"completed_tasks\":{},\
\"verified_inputs\":{},\"inputs_in_failed_txs\":{},\"script_failure_txs\":{},\
\"immature_violations\":{},\"value_violations\":{},\"nonfinal_violations\":{},\
\"time_locks_unevaluated\":{},\"sigop_violations\":{},\
\"bip68_evaluated\":{},\"bip68_violations\":{},\"bip68_unevaluated\":{},\
\"cb_bound_checks\":{},\"cb_bound_violations\":{},\
\"headers_loaded\":{},\"headers_inserted\":{},\"headers_unknown_parent\":{},\
\"headers_failed\":{},\"window_headers_in_tree\":{},\
\"headers_height_mismatch\":{},\"headers_chain_mismatch\":{},\
\"headers_failed_selected\":{},\"headers_missing_selected\":{},\
\"headers_chain_missing\":{},\
\"ctx_block_evaluated\":{},\"ctx_block_failed\":{},\"ctx_block_unevaluated\":{},\
\"survivor_records\":{},\"applied_events\":{},\
\"first_bad_height\":{},\"first_bad\":{},\
\"known_invalid\":{},\
\"resolved_inputs_complete\":{},\"script_jobs_complete\":{},\
\"starting_state_complete\":{},\"boundary_loaded_coins\":{},\
\"boundary_base_height\":{},\"boundary_base_hash\":{},\
\"boundary_txoutset_hash\":{},\"boundary_dup_outpoints\":{},\
\"first_missing_height\":{},\
\"header_context_checked\":{},\"header_context_full\":{},\
\"contextual_blocks_complete\":{},\"all_donor_pins\":{},\
\"window_complete\":{},\
\"context_free_checks_complete\":{},\"coverage_endpoints\":{},\"coverage_complete\":{},\
\"chainstate_complete\":{},\
\"exported\":{},\
\"stages\":{{\"parse_s\":{:.3},\"emit_s\":{:.3},\"headers_s\":{:.3},\
\"boundary_load_s\":{:.3},\"join_s\":{:.3},\
\"predicate_s\":{:.3},\"script_s\":{:.3},\"materialize_s\":{:.3},\
\"export_s\":{:.3}}},\"wall_s\":{:.3},\"rss_hwm_bytes\":{},\"workers\":{}}}",
        window_lo,
        window_hi,
        corpus_bytes,
        blocks.len(),
        (window_hi - window_lo + 1),
        missing_heights,
        dup_heights,
        longest_run,
        header_hash_verified,
        linkage_checked,
        linkage_broken,
        mtp_computable,
        ctx_free_failed,
        n_txs,
        n_inputs_noncb,
        n_srcs_resolved,
        n_srcs_unresolved,
        gap_heights_sourced,
        spends.len(),
        created.len(),
        boundary_coins_report,
        boundary_conflicts,
        report.violations.len(),
        report.dup_spends,
        report.missing_spends,
        fully_resolved_txs,
        excluded_txs,
        resolved_spec_unjoined,
        unresolved_spec_inputs,
        blocks_fully_covered,
        exec_inputs,
        queued_tasks,
        completed_tasks,
        succeeded_inputs,
        inputs_in_failed_txs,
        failed_tasks,
        immature_violations,
        value_violations,
        nonfinal_violations,
        time_locks_unevaluated,
        sigop_violations,
        bip68_evaluated,
        bip68_violations,
        bip68_unevaluated,
        cb_bound_checks,
        cb_bound_violations,
        headers_loaded,
        headers_inserted,
        headers_unknown_parent,
        headers_failed,
        window_headers_in_tree,
        headers_height_mismatch,
        headers_chain_mismatch,
        headers_failed_selected,
        headers_missing_selected,
        headers_chain_missing,
        ctx_block_evaluated,
        ctx_block_failed,
        ctx_block_unevaluated,
        boundary.alive_indices().count() + extra.len(),
        applied_events,
        if first_bad_h == u32::MAX {
            "null".into()
        } else {
            first_bad_h.to_string()
        },
        if first_bad_msg.is_empty() {
            "null".into()
        } else {
            jstr(&first_bad_msg)
        },
        known_invalid,
        resolved_inputs_complete,
        script_jobs_complete,
        starting_state_complete,
        boundary_load_coins,
        boundary_base_height
            .map(|h| h.to_string())
            .unwrap_or_else(|| "null".into()),
        boundary_base_hash_json,
        boundary_txoutset_hash_json,
        boundary_dup_outpoints,
        report
            .first_missing
            .map(|o| o.h.to_string())
            .unwrap_or_else(|| "null".into()),
        header_context_checked,
        header_context_full,
        contextual_blocks_complete,
        all_pins,
        window_complete,
        context_free_checks_complete,
        coverage_endpoints,
        coverage_complete,
        window_complete && exported,
        exported,
        parse_s,
        emit_s,
        headers_s,
        boundary_load_s,
        join_s,
        pred_s,
        script_s,
        mat_s,
        export_s,
        wall_t.elapsed().as_secs_f64(),
        rss,
        workers,
    );

    // ---- exit: ONE contract -------------------------------------------
    // Known invalidity → 1 in BOTH modes (diagnostic permits coverage
    // gaps, never acceptance of detected invalidity). Strict → 1 on any
    // unresolved inputs, failed script jobs, or unverifiable selected
    // headers (missing context). `--require-complete` → 1 unless every
    // applicable check ran and passed (window_complete). Diagnostic
    // incomplete-but-clean → 0. Computed ONCE so the manifest records
    // the same exit the process takes.
    let exit_code = if known_invalid {
        eprintln!("invalid: {first_bad_msg} @ {first_bad_h}");
        1
    } else if !diagnostic
        && (!(resolved_inputs_complete && script_jobs_complete)
            || headers_missing_selected > 0
            || headers_chain_missing > 0
            || !coverage_endpoints)
    {
        eprintln!(
            "incomplete: missing_spends={} failed_tasks={} headers_missing_selected={} \
headers_chain_missing={} coverage_endpoints={}",
            report.missing_spends,
            failed_tasks,
            headers_missing_selected,
            headers_chain_missing,
            coverage_endpoints
        );
        1
    } else if require_complete && !window_complete {
        eprintln!(
            "incomplete: window_complete=false (pins={} hdr_ctx={} ctx_blocks={} \
bip68_uneval={} time_locks_uneval={})",
            all_pins,
            header_context_full,
            contextual_blocks_complete,
            bip68_unevaluated,
            time_locks_unevaluated
        );
        1
    } else {
        0
    };

    // ---- run manifest: source + binary + inputs + outputs, one record --
    // Lets an auditor prove WHICH binary produced WHICH output from
    // WHICH inputs. `build_rev` is embedded at COMPILE time by build.rs
    // (an older binary can never report a newer checkout); `checkout_rev`
    // is the checkout's runtime HEAD, labeled separately. Streams all
    // file hashes — no whole-file Vec reads at snapshot sizes.
    if let Some(rm) = &run_manifest_path {
        let self_sha = file_sha256("/proc/self/exe");
        let boundary_sha = boundary_path.as_ref().and_then(|p| file_sha256(p));
        let headers_sha = headers_path.as_ref().and_then(|p| file_sha256(p));
        let export_sha = if exported {
            file_sha256(&export_path)
        } else {
            None
        };
        let checkout_rev = std::process::Command::new("git")
            .args([
                "-C",
                concat!(env!("CARGO_MANIFEST_DIR"), "/../.."),
                "rev-parse",
                "HEAD",
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".into());
        let argv_json = std::env::args()
            .skip(1)
            .map(|a| jstr(&a))
            .collect::<Vec<_>>()
            .join(",");
        let wall_s_total = wall_t.elapsed().as_secs_f64();
        let manifest = format!(
            "{{\"type\":\"run_manifest\",\
\"build_rev\":{},\"checkout_rev\":{},\
\"binary_sha256\":{},\"corpus_sha256\":{},\
\"boundary_sha256\":{},\"headers_sha256\":{},\"export_sha256\":{},\
\"argv\":[{}],\"exit_code\":{},\"known_invalid\":{},\"exported\":{},\
\"wall_s_total\":{:.3}}}",
            jstr(option_env!("AVILA_GIT_REV").unwrap_or("unknown")),
            jstr(&checkout_rev),
            self_sha.map(|s| jstr(&s)).unwrap_or("null".into()),
            jstr(&corpus_sha256),
            boundary_sha.map(|s| jstr(&s)).unwrap_or("null".into()),
            headers_sha.map(|s| jstr(&s)).unwrap_or("null".into()),
            export_sha.map(|s| jstr(&s)).unwrap_or("null".into()),
            argv_json,
            exit_code,
            known_invalid,
            exported,
            wall_s_total,
        );
        std::fs::write(rm, manifest + "\n").expect("run manifest writable");
    }
    std::process::exit(exit_code);
}

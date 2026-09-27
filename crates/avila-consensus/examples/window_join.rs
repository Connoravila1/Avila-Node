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
use avila_consensus::check::{MAX_BLOCK_SIGOPS_COST, MAX_MONEY, check_block, is_final_tx};
use avila_consensus::connect::{COINBASE_MATURITY, Coin, block_subsidy, tx_sigop_cost};
use avila_consensus::hash::{BlockHash, sha256};
use avila_consensus::header::BlockHeader;
use avila_consensus::params::Network;
use avila_consensus::script::{ScriptFlags, block_script_flags};
use avila_consensus::sigchecker::check_input_scripts;
use avila_consensus::snapverify::for_each_coin;
use avila_consensus::transaction::{OutPoint, Script, Transaction, TxOut};
use std::collections::HashMap;

#[path = "shared/join_engine.rs"]
mod join_engine;
use join_engine::{Creation, JoinRes, Occ, Spend, build_boundary, join_window};

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

fn canonical_bytes(map: &HashMap<OutPoint, Coin>) -> Vec<u8> {
    let mut recs: Vec<(&OutPoint, &Coin)> = map.iter().collect();
    recs.sort_by_key(|a| (a.0.txid, a.0.vout));
    let mut out = Vec::with_capacity(recs.len() * 48);
    for (op, c) in recs {
        out.extend_from_slice(op.txid.as_bytes());
        out.extend_from_slice(&op.vout.to_le_bytes());
        out.extend_from_slice(&c.out.value.to_le_bytes());
        let spk = c.out.script_pubkey.as_bytes();
        out.extend_from_slice(&(spk.len() as u32).to_le_bytes());
        out.extend_from_slice(spk);
        out.extend_from_slice(&c.height.to_le_bytes());
        out.push(u8::from(c.coinbase));
    }
    out
}

fn money_range(v: i64) -> bool {
    (0..=MAX_MONEY).contains(&v)
}

fn jstr(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

fn hexid(h: &BlockHash) -> String {
    h.as_bytes()
        .iter()
        .rev()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn main() {
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
    assert!(!blocks.is_empty());
    let parse_s = t.elapsed().as_secs_f64();
    let window_lo = blocks.first().unwrap().height;
    let window_hi = blocks.last().unwrap().height;
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
        if present_heights.contains(&(b.height - 1)) {
            linkage_checked += 1;
            let parent_ok = by_hash
                .get(&b.header.prev_block_hash)
                .is_some_and(|p| p.height == b.height - 1);
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
        if let Some(m) = mtp_of(b.height - 1) {
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

    // ---- stage A: context-free block checks + ledger emit -------------
    let t = std::time::Instant::now();
    let mut first_bad_h = u32::MAX;
    let mut first_bad_msg = String::new();
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
    let mut boundary_loaded: Option<HashMap<OutPoint, Coin>> = None;
    let mut boundary_load_coins = 0usize;
    let mut boundary_dup_outpoints = 0usize;
    let mut boundary_base_height: Option<u32> = None;
    let mut boundary_base_hash_json = "null".to_string();
    if let Some(bp) = &boundary_path {
        // A supplied boundary is meaningful only as the state at the
        // window's parent block: the corpus's first block must name it
        // (the audit's comparison window starts "immediately after" the
        // exported boundary).
        let base_height = blocks[0].height.wrapping_sub(1);
        boundary_base_height = Some(base_height);
        let mut m: HashMap<OutPoint, Coin> = HashMap::new();
        let mut dups = 0usize;
        let snap_hdr = for_each_coin(
            std::path::Path::new(bp),
            Some(base_height), // creation heights may not exceed the base
            |txid_b, vout, code, value, spk| {
                let txid = avila_consensus::hash::Txid::from_bytes(txid_b);
                if m.insert(
                    OutPoint { txid, vout },
                    Coin {
                        out: TxOut {
                            value,
                            script_pubkey: Script::new(spk.to_vec()),
                        },
                        height: (code >> 1) as u32,
                        coinbase: code & 1 != 0,
                    },
                )
                .is_some()
                {
                    dups += 1; // a dump cannot name one outpoint twice
                }
                Ok(())
            },
        )
        .unwrap_or_else(|e| {
            eprintln!("fatal: --boundary load failed: {e}");
            std::process::exit(2);
        });
        boundary_dup_outpoints = dups;
        if boundary_dup_outpoints > 0 {
            eprintln!("fatal: boundary contains {boundary_dup_outpoints} duplicate outpoints");
            std::process::exit(2);
        }
        boundary_load_coins = m.len();
        if snap_hdr.network != params.message_start {
            eprintln!(
                "fatal: boundary network {:02x?} ≠ params {:02x?}",
                snap_hdr.network, params.message_start
            );
            std::process::exit(2);
        }
        if let Some(pin) = &boundary_base_hash {
            // dumptxoutset reports display-order; file stores LE bytes
            let want: Vec<u8> = (0..32)
                .map(|i| u8::from_str_radix(&pin[60 - i * 2..62 - i * 2], 16))
                .collect::<Result<_, _>>()
                .expect("--boundary-base-hash hex");
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
        let disp: Vec<u8> = snap_hdr.base_blockhash.iter().rev().cloned().collect();
        boundary_base_hash_json = jstr(&avila_consensus::hex::encode(&disp));
        boundary_loaded = Some(m);
    }
    let (boundary, boundary_conflicts, conflict_ops) = if let Some(loaded) = &boundary_loaded {
        // specs vs supplied state: agreement is consistency-verified;
        // disagreement marks the outpoint conflicted (known invalidity).
        let mut conflict_ops: std::collections::HashSet<OutPoint> = Default::default();
        for (op, spec_coin) in &boundary_specs {
            match loaded.get(op) {
                Some(c) if c == spec_coin => {}
                _ => {
                    conflict_ops.insert(*op);
                }
            }
        }
        (loaded.clone(), conflict_ops.len(), conflict_ops)
    } else {
        build_boundary(boundary_specs.into_iter())
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
    let missing_is_invalid = boundary_loaded.is_some();
    let known_invalid = first_bad_h != u32::MAX
        || !report.violations.is_empty()
        || report.dup_spends > 0
        || boundary_conflicts > 0
        || failed_tasks > 0
        || ctx_free_failed > 0
        || linkage_broken > 0
        || (missing_is_invalid && report.missing_spends > 0);

    // ---- stage E: materialize valid-prefix survivor set ----------------
    let t = std::time::Instant::now();
    let mut live: HashMap<OutPoint, Coin> = boundary.clone();
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
            live.insert(created[k].op, created[k].coin.clone());
        } else {
            live.remove(&spends[k].op);
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
    let starting_state_complete = boundary_loaded.is_some();
    let header_context_checked = linkage_broken == 0 && linkage_checked > 0;
    let context_free_checks_complete = ctx_free_failed == 0;
    let coverage_complete = missing_heights == 0 && dup_heights == 0;

    // ---- stage F: export — only when a state may legitimately exist ----
    // Never exported on known invalidity (either mode). In strict mode a
    // state artifact additionally requires full input coverage.
    let t = std::time::Instant::now();
    let mut exported = false;
    let may_publish =
        !known_invalid && (diagnostic || (resolved_inputs_complete && script_jobs_complete));
    if may_publish {
        let canonical = canonical_bytes(&live);
        let mut f = std::fs::File::create(&export_path).unwrap_or_else(|e| {
            eprintln!("fatal: cannot create {export_path}: {e}");
            std::process::exit(2);
        });
        use std::io::Write;
        f.write_all(&canonical).unwrap_or_else(|e| {
            eprintln!("fatal: export write failed: {e}");
            std::process::exit(2);
        });
        f.sync_all().unwrap_or_else(|e| {
            eprintln!("fatal: export sync failed: {e}");
            std::process::exit(2);
        });
        exported = true;
        let d = sha256(&canonical);
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        println!(
            "{{\"type\":\"export\",\"path\":{},\"bytes\":{},\"sha256\":{},\
\"chainstate_complete\":false,\"projection\":\"valid_prefix\"}}",
            jstr(&export_path),
            canonical.len(),
            jstr(&hex)
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
\"cb_bound_checks\":{},\"cb_bound_violations\":{},\
\"survivor_records\":{},\"applied_events\":{},\
\"first_bad_height\":{},\"first_bad\":{},\
\"known_invalid\":{},\
\"resolved_inputs_complete\":{},\"script_jobs_complete\":{},\
\"starting_state_complete\":{},\"boundary_loaded_coins\":{},\
\"boundary_base_height\":{},\"boundary_base_hash\":{},\
\"boundary_dup_outpoints\":{},\
\"header_context_checked\":{},\
\"context_free_checks_complete\":{},\"coverage_complete\":{},\
\"chainstate_complete\":false,\
\"exported\":{},\
\"stages\":{{\"parse_s\":{:.3},\"emit_s\":{:.3},\"join_s\":{:.3},\
\"predicate_s\":{:.3},\"script_s\":{:.3},\"materialize_s\":{:.3},\
\"export_s\":{:.3}}},\"rss_hwm_bytes\":{},\"workers\":{}}}",
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
        boundary.len(),
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
        cb_bound_checks,
        cb_bound_violations,
        live.len(),
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
        boundary_dup_outpoints,
        header_context_checked,
        context_free_checks_complete,
        coverage_complete,
        exported,
        parse_s,
        emit_s,
        join_s,
        pred_s,
        script_s,
        mat_s,
        export_s,
        rss,
        workers,
    );

    // ---- exit: ONE contract -------------------------------------------
    // Known invalidity → 1 in BOTH modes (diagnostic permits coverage
    // gaps, never acceptance of detected invalidity). Incomplete
    // coverage under strict → 1. Diagnostic incomplete-but-clean → 0.
    if known_invalid {
        eprintln!("invalid: {first_bad_msg} @ {first_bad_h}");
        std::process::exit(1);
    }
    if !(resolved_inputs_complete && script_jobs_complete) && !diagnostic {
        eprintln!(
            "incomplete: missing_spends={} failed_tasks={failed_tasks}",
            report.missing_spends
        );
        std::process::exit(1);
    }

    // ---- run manifest: source + binary + inputs + outputs, one record --
    // Lets an auditor prove WHICH binary produced WHICH output from
    // WHICH inputs — the audit found the archived binary hash had
    // drifted from the executable, so the identity goes into the file.
    if let Some(rm) = &run_manifest_path {
        let self_sha = std::fs::read("/proc/self/exe")
            .map(|b| sha256(&b))
            .map(|h| avila_consensus::hex::encode(&h))
            .ok();
        let corpus_sha = corpus_sha256;
        let boundary_sha = boundary_path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .map(|b| avila_consensus::hex::encode(&sha256(&b)));
        let export_sha = if exported {
            std::fs::read(&export_path)
                .ok()
                .map(|b| avila_consensus::hex::encode(&sha256(&b)))
        } else {
            None
        };
        let git_rev = std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|| "unknown".into());
        let manifest = format!(
            "{{\"type\":\"run_manifest\",\"git_rev\":{},\
\"binary_sha256\":{},\"corpus_sha256\":{},\
\"boundary_sha256\":{},\"export_sha256\":{},\
\"args\":{},\"known_invalid\":{},\"exported\":{}}}",
            jstr(&git_rev),
            self_sha.map(|s| jstr(&s)).unwrap_or("null".into()),
            jstr(&corpus_sha),
            boundary_sha.map(|s| jstr(&s)).unwrap_or("null".into()),
            export_sha.map(|s| jstr(&s)).unwrap_or("null".into()),
            jstr(&std::env::args().skip(1).collect::<Vec<_>>().join(" ")),
            known_invalid,
            exported,
        );
        std::fs::write(rm, manifest + "\n").expect("run manifest writable");
    }
}

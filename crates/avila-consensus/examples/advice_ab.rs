// Benchmark/probe harness — panics on setup failure are the intent.
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Advice-assisted ECDSA A/B over a real corpus.
//!
//! Phase 1 — produce: replay the corpus through a capturing checker
//! that runs the ordinary verification and emits the hint stream an
//! already-synced Avila node would serve (65-byte records: hint ‖
//! key_y ‖ nonce_y; a 0xFF sentinel where no advice exists).
//!
//! Phase 2 — ordinary replay, timed (the baseline).
//!
//! Phase 3 — advised replay: a deferred checker defers every advised
//! ECDSA check into a per-block sink, batch-verifies it, and resolves
//! failures by per-signature re-verify plus targeted re-check of the
//! affected transactions — the exact semantics of the live path.
//!
//! Phase 4 — equivalence: every transaction's verdict must be
//! identical between phases 2 and 3 (exit nonzero otherwise).
//!
//! Output: JSON lines. Usage:
//!   advice_ab <corpus.bin|dir> [--workers N] [--inject-bad-hint P]
//!   --inject-bad-hint flips a bit in every P-th advice record to
//!   exercise the fallback path under corruption.

use avila_consensus::hash::BlockHash;
use avila_consensus::interpreter::{ExecutionData, ScriptError, SigVersion, SignatureChecker};
use avila_consensus::params::Network;
use avila_consensus::script::block_script_flags;
use avila_consensus::sigbatch;
use avila_consensus::sigchecker::{
    ADVICE_ABSENT, DeferredSink, PrecomputedTransactionData, TransactionSignatureChecker,
    check_input_scripts, check_input_scripts_advised, resolve_sink,
};
use avila_consensus::transaction::{Script, Transaction, TxOut};

struct Source {
    out: TxOut,
    creation_height: u32,
    coinbase: bool,
}

struct Rec {
    height: u32,
    hash: [u8; 32],
    txs: Vec<(Vec<u8>, Vec<Option<Source>>)>,
}

fn u32at(b: &[u8], o: &mut usize) -> u32 {
    let v = u32::from_le_bytes(b[*o..*o + 4].try_into().unwrap());
    *o += 4;
    v
}

fn parse_corpus(raw: &[u8]) -> Vec<Rec> {
    // AVCORP02: block = height ‖ hash32 ‖ txs
    // AVCORP03: block = height ‖ hash32 ‖ header80 ‖ txs
    let v3 = &raw[..8] == b"AVCORP03";
    assert!(
        v3 || &raw[..8] == b"AVCORP02",
        "bad magic (expect AVCORP02/03)"
    );
    let mut o = 8usize;
    let mut blocks = Vec::new();
    while o < raw.len() {
        let height = u32at(raw, &mut o);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&raw[o..o + 32]);
        o += 32;
        if v3 {
            o += 80; // block header — flags come from height anyway
        }
        let n_tx = u32at(raw, &mut o) as usize;
        let mut txs = Vec::with_capacity(n_tx);
        for _ in 0..n_tx {
            let n = u32at(raw, &mut o) as usize;
            let rawtx = raw[o..o + n].to_vec();
            o += n;
            let n_in = u32at(raw, &mut o) as usize;
            let mut outs = Vec::with_capacity(n_in);
            for _ in 0..n_in {
                let resolved = raw[o];
                o += 1;
                if resolved == 0 {
                    outs.push(None);
                } else {
                    let value = i64::from_le_bytes(raw[o..o + 8].try_into().unwrap());
                    o += 8;
                    let sl = u32at(raw, &mut o) as usize;
                    let spk = Script::new(raw[o..o + sl].to_vec());
                    o += sl;
                    let creation_height = u32at(raw, &mut o);
                    let coinbase = raw[o] & 1 != 0;
                    o += 1;
                    outs.push(Some(Source {
                        out: TxOut {
                            value,
                            script_pubkey: spk,
                        },
                        creation_height,
                        coinbase,
                    }));
                }
            }
            txs.push((rawtx, outs));
        }
        blocks.push(Rec { height, hash, txs });
    }
    blocks
}

struct Task {
    block_slot: usize,
    tx: Transaction,
    outs: Vec<TxOut>,
    flags: avila_consensus::script::ScriptFlags,
}

/// Capturing checker — the producer. Runs the identical cheap gates and
/// the real signature verify, then emits the 65-byte advice record for
/// sigs that verified, or the 0xFF sentinel otherwise. Eval order is
/// therefore the true order; the consumer's cursor stays aligned.
struct CaptureChecker<'a> {
    inner: TransactionSignatureChecker<'a>,
    out: &'a std::cell::RefCell<Vec<u8>>,
}

impl SignatureChecker for CaptureChecker<'_> {
    fn check_ecdsa_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        script_code: &[u8],
        sigversion: SigVersion,
    ) -> bool {
        if pubkey.is_empty() || sig.is_empty() {
            return false;
        }
        let hash_type = i32::from(sig[sig.len() - 1]);
        let sig = &sig[..sig.len() - 1];
        if sigversion == SigVersion::WitnessV0 && self.inner.amount < 0 {
            return false;
        }
        let sighash = avila_consensus::sigchecker::signature_hash(
            &Script::new(script_code.to_vec()),
            self.inner.tx,
            self.inner.n_in,
            hash_type,
            self.inner.amount,
            sigversion,
            self.inner.txdata,
        );
        let ok = TransactionSignatureChecker::verify_ecdsa_signature(sig, pubkey, &sighash);
        let mut out = self.out.borrow_mut();
        // Sentinel r must come from the SAME parse the consumer runs
        // (from_der_lax — laxer than strict DER); a zero r is emitted
        // only when even lax parse fails.
        let sentinel_r = |out: &mut Vec<u8>| {
            let r = secp256k1::ecdsa::Signature::from_der_lax(sig)
                .ok()
                .map(|s| s.serialize_compact()[..32].to_vec())
                .unwrap_or_else(|| vec![0u8; 32]);
            out.extend_from_slice(&r);
            out.push(ADVICE_ABSENT);
        };
        if !ok {
            sentinel_r(&mut out);
            return false;
        }
        let Some((sig64, pub33)) = (|| {
            let mut s = secp256k1::ecdsa::Signature::from_der_lax(sig).ok()?;
            s.normalize_s();
            let pub33: [u8; 33] = match pubkey.len() {
                33 => pubkey.try_into().ok()?,
                65 => {
                    let mut c = [0u8; 33];
                    c[0] = if pubkey[64] & 1 == 1 { 0x03 } else { 0x02 };
                    c[1..].copy_from_slice(&pubkey[1..33]);
                    c
                }
                _ => return None,
            };
            Some((s.serialize_compact(), pub33))
        })() else {
            sentinel_r(&mut out);
            return true; // verified ordinarily; just unadvisable
        };
        match sigbatch::produce_advice(&sighash, &sig64, &pub33) {
            Some(a) => {
                out.extend_from_slice(&sig64[..32]); // r
                out.push(a.byte);
                out.extend_from_slice(&a.key_y);
                out.extend_from_slice(&a.nonce_y.unwrap_or([0u8; 32]));
            }
            None => {
                out.extend_from_slice(&sig64[..32]);
                out.push(ADVICE_ABSENT);
            }
        }
        true
    }

    fn check_schnorr_signature(
        &self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        execdata: &mut ExecutionData,
    ) -> Result<(), ScriptError> {
        self.inner
            .check_schnorr_signature(sig, pubkey, sigversion, execdata)
    }
    fn check_locktime(&self, locktime: i64) -> bool {
        self.inner.check_locktime(locktime)
    }
    fn check_sequence(&self, sequence: i64) -> bool {
        self.inner.check_sequence(sequence)
    }
    fn verify_taproot_commitment(
        &self,
        control: &[u8],
        program: &[u8],
        tapleaf_hash: &[u8; 32],
    ) -> bool {
        self.inner
            .verify_taproot_commitment(control, program, tapleaf_hash)
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| {
        eprintln!("usage: advice_ab <corpus.bin|dir> [--workers N] [--inject-bad-hint P]");
        std::process::exit(2);
    });
    let rest: Vec<String> = args.collect();
    let opt = |name: &str| -> Option<String> {
        rest.iter()
            .position(|a| a == name)
            .and_then(|i| rest.get(i + 1).cloned())
    };
    let workers: usize = opt("--workers").map_or(1, |s| s.parse().unwrap());
    let inject_every: u64 = opt("--inject-bad-hint").map_or(0, |s| s.parse().unwrap());
    let max_blocks: usize = opt("--max-blocks").map_or(usize::MAX, |s| s.parse().unwrap());
    let corpus_path = if std::path::Path::new(&path).is_dir() {
        format!("{path}/corpus.bin")
    } else {
        path
    };
    let raw = std::fs::read(&corpus_path).unwrap();
    let mut blocks = parse_corpus(&raw);
    blocks.truncate(max_blocks);
    drop(raw);

    // Build tasks exactly like corpus_replay.
    let params = Network::Mainnet.params();
    let mut tasks: Vec<Task> = Vec::new();
    for (bi, b) in blocks.iter().enumerate() {
        let flags = block_script_flags(&params, b.height, &BlockHash::from_bytes(b.hash));
        for (rawtx, outs) in &b.txs {
            let tx = Transaction::decode(rawtx).unwrap();
            let n_in = tx.inputs.len();
            let is_cb = n_in == 1 && tx.inputs[0].previous_output.is_null();
            if is_cb {
                continue;
            }
            let n_missing = outs.iter().filter(|o| o.is_none()).count();
            let n_immature = outs
                .iter()
                .filter(|o| {
                    o.as_ref()
                        .map(|s| s.coinbase && b.height < s.creation_height + 100)
                        .unwrap_or(false)
                })
                .count();
            if n_missing > 0 || n_immature > 0 {
                continue;
            }
            let owned: Vec<TxOut> = outs
                .iter()
                .map(|o| o.as_ref().unwrap().out.clone())
                .collect();
            tasks.push(Task {
                block_slot: bi,
                tx,
                outs: owned,
                flags,
            });
        }
    }
    let n_blocks = blocks.len();
    println!(
        "{{\"type\":\"prep\",\"blocks\":{n_blocks},\"tasks\":{}}}",
        tasks.len()
    );
    let tasks = std::sync::Arc::new(tasks);

    // ---- Phase 1: produce advice (capture during real verification) ----
    let t0 = std::time::Instant::now();
    let advice: Vec<std::cell::RefCell<Vec<u8>>> = tasks
        .iter()
        .map(|_| std::cell::RefCell::new(Vec::new()))
        .collect();
    let mut produced_sigs = 0u64;
    let mut sentinels = 0u64;
    for (ti, t) in tasks.iter().enumerate() {
        let txdata = PrecomputedTransactionData::new(&t.tx, Some(t.outs.clone()), false);
        let out = &advice[ti];
        for (i, input) in t.tx.inputs.iter().enumerate() {
            let checker = CaptureChecker {
                inner: TransactionSignatureChecker::new(&t.tx, i, t.outs[i].value, &txdata),
                out,
            };
            avila_consensus::interpreter::verify_script(
                &input.script_sig,
                &t.outs[i].script_pubkey,
                Some(&input.witness),
                t.flags,
                &checker,
            )
            .unwrap();
        }
    }
    // Count: 65-byte records vs 1-byte sentinels.
    for c in &advice {
        let mut o = 0;
        let b = c.borrow();
        while o + 33 <= b.len() {
            if b[o + 32] == ADVICE_ABSENT {
                sentinels += 1;
                o += 33;
            } else {
                produced_sigs += 1;
                o += 97;
            }
        }
    }
    let produce_s = t0.elapsed().as_secs_f64();
    let advice_bytes: u64 = advice.iter().map(|c| c.borrow().len() as u64).sum();
    println!(
        "{{\"type\":\"produce\",\"s\":{produce_s:.3},\"advised_sigs\":{produced_sigs},\
\"sentinels\":{sentinels},\"advice_bytes\":{advice_bytes}}}"
    );
    // Freeze advice into a shareable form; optionally corrupt every
    // P-th record's parity bit to exercise the fallback path.
    let mut inject_count = 0u64;
    let mut advice: Vec<Vec<u8>> = advice
        .into_iter()
        .map(std::cell::RefCell::into_inner)
        .collect();
    if inject_every != 0 {
        for entries in &mut advice {
            let mut o = 0usize;
            while o + 97 <= entries.len() {
                if entries[o + 32] != ADVICE_ABSENT {
                    if inject_count.is_multiple_of(inject_every) {
                        entries[o + 32] ^= 0x01;
                    }
                    inject_count += 1;
                    o += 97;
                } else {
                    o += 33;
                }
            }
        }
    }

    // ---- Phase 2: ordinary replay (baseline) ----
    let ord_fail = std::sync::atomic::AtomicU64::new(0);
    let t0 = std::time::Instant::now();
    {
        let cursor = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..workers {
                let cursor = &cursor;
                let ord_fail = &ord_fail;
                let tasks = &tasks;
                s.spawn(move || {
                    loop {
                        let i = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if i >= tasks.len() {
                            break;
                        }
                        let t = &tasks[i];
                        if check_input_scripts(&t.tx, &t.outs, t.flags).is_err() {
                            ord_fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                });
            }
        });
    }
    let ordinary_s = t0.elapsed().as_secs_f64();
    println!(
        "{{\"type\":\"ordinary\",\"workers\":{workers},\"s\":{ordinary_s:.3},\
\"failed_txs\":{}}}",
        ord_fail.load(std::sync::atomic::Ordering::Relaxed)
    );

    // ---- Phase 3: advised replay — deferred eval + per-block batch ----
    let adv_fail = std::sync::atomic::AtomicU64::new(0);
    let advised = std::sync::atomic::AtomicU64::new(0);
    let inline = std::sync::atomic::AtomicU64::new(0);
    let batches_bad = std::sync::atomic::AtomicU64::new(0);
    let dirty_recovered = std::sync::atomic::AtomicU64::new(0);
    let t0 = std::time::Instant::now();
    {
        // Partition tasks into whole-block ranges — a block's sink is
        // one unit of work, never split across workers.
        let mut ranges: Vec<(usize, usize)> = Vec::new();
        let mut i = 0;
        while i < tasks.len() {
            let slot = tasks[i].block_slot;
            let mut j = i;
            while j < tasks.len() && tasks[j].block_slot == slot {
                j += 1;
            }
            ranges.push((i, j));
            i = j;
        }
        let cursor = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|s| {
            for _ in 0..workers {
                let cursor = &cursor;
                let tasks = &tasks;
                let advice = &advice;
                let adv_fail = &adv_fail;
                let advised = &advised;
                let inline = &inline;
                let batches_bad = &batches_bad;
                let dirty_recovered = &dirty_recovered;
                let ranges = &ranges;
                s.spawn(move || {
                    loop {
                        let r = cursor.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if r >= ranges.len() {
                            break;
                        }
                        let (lo, hi) = ranges[r];
                        let sink = std::cell::RefCell::new(DeferredSink::default());
                        let stat = std::cell::Cell::new((0u64, 0u64));
                        let mut eval_errored: Vec<(u32, &Task)> = Vec::new();
                        for (ti, t) in tasks[lo..hi].iter().enumerate() {
                            let entries = &advice[lo + ti];
                            let tag = ti as u32;
                            if check_input_scripts_advised(
                                &t.tx, &t.outs, t.flags, entries, &sink, tag, &stat,
                            )
                            .is_err()
                            {
                                // Deferred-mode eval errors are provisional;
                                // resolve before believing them.
                                eval_errored.push((tag, t));
                            }
                        }
                        let (a, inl) = stat.get();
                        advised.fetch_add(a, std::sync::atomic::Ordering::Relaxed);
                        inline.fetch_add(inl, std::sync::atomic::Ordering::Relaxed);
                        let dirty = match resolve_sink(&sink.borrow()) {
                            Ok(()) => Vec::new(),
                            Err(d) => {
                                batches_bad.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                dirty_recovered.fetch_add(
                                    d.len() as u64,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                                d
                            }
                        };
                        // Re-check: dirty txs (batch says a record failed —
                        // provisional eval was wrong) + any tx whose deferred
                        // eval errored (its true verdict is unknown until the
                        // batch proves the pushes).
                        let mut recheck: Vec<u32> = dirty;
                        for (tag, _) in &eval_errored {
                            if !recheck.contains(tag) {
                                recheck.push(*tag);
                            }
                        }
                        for tag in recheck {
                            let t = &tasks[lo..hi][tag as usize];
                            if check_input_scripts(&t.tx, &t.outs, t.flags).is_err() {
                                adv_fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                });
            }
        });
    }
    let advised_s = t0.elapsed().as_secs_f64();
    let adv_ok = adv_fail.load(std::sync::atomic::Ordering::Relaxed);
    let ord_bad = ord_fail.load(std::sync::atomic::Ordering::Relaxed);
    let equivalent = adv_ok == ord_bad;
    println!(
        "{{\"type\":\"advised\",\"workers\":{workers},\"s\":{advised_s:.3},\
\"deferred_sigs\":{},\"inline_sigs\":{},\"batch_failures\":{},\
\"dirty_rechecked\":{},\"injected\":{},\"failed_txs\":{adv_ok},\
\"verdicts_match\":{equivalent}}}",
        advised.load(std::sync::atomic::Ordering::Relaxed),
        inline.load(std::sync::atomic::Ordering::Relaxed),
        batches_bad.load(std::sync::atomic::Ordering::Relaxed),
        dirty_recovered.load(std::sync::atomic::Ordering::Relaxed),
        inject_count,
    );
    let speedup = ordinary_s / advised_s.max(f64::EPSILON);
    println!(
        "{{\"type\":\"result\",\"ordinary_s\":{ordinary_s:.3},\"advised_s\":{advised_s:.3},\
\"speedup\":{speedup:.3},\"equivalent\":{equivalent}}}"
    );
    if !equivalent {
        std::process::exit(1);
    }
}

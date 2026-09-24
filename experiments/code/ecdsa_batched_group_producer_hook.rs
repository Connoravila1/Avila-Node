//! Isolated bounded producer batching with exact result memoization.
//! Fork of ecdsa_stream_hook.rs; ordinary ECDSA arithmetic supplies every producer verdict.
//! A pool job completes only AFTER its group's equations pass or ordinary
//! Script replay supplies the verdict. Advice never supplies trusted false.
use crate::experimental_advice_codec as codec;
pub use codec::Token;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::interpreter::ScriptError;
use crate::transaction::Transaction;

const MAX_BATCH: usize = 8192;
const MAX_HINT_FILE: u64 = 32 << 20;
const MAX_TX_HINTS: usize = 80_000;
static SESSION: OnceLock<Session> = OnceLock::new();
thread_local! {
    static GROUP: RefCell<Option<Group>> = const { RefCell::new(None) };
    static TOKEN: RefCell<Token> = const { RefCell::new(None) };
}

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub checks: u64,
    pub produced: u64,
    pub producer_replays: u64,
    pub producer_replay_checks: u64,
    pub producer_cache_hits: u64,
    pub producer_cache_overflow: u64,
    pub producer_peak_cache: u64,
    pub stream_bytes: u64,
    pub stream_frames: u64,
    pub stream_missed: u64,
    pub stream_rejected: u64,
    pub peak_frames: u64,
    pub peak_hint_bytes: u64,
    pub hinted: u64,
    pub ordinary: u64,
    pub false_checks: u64,
    pub batches: u64,
    pub direct: u64,
    pub failed_batches: u64,
    pub worker_errors: u64,
    pub retry_groups: u64,
    pub retry_checks: u64,
    pub max_retry_jobs: u64,
    pub groups: u64,
    pub max_pending: u64,
    pub worker_cpu_ns: u64,
    pub workers: u64,
    pub hints_bytes: u64,
    pub sidecar_rejected: bool,
    pub disabled: bool,
}

impl Stats {
    fn add(&mut self, other: &Self) {
        self.checks += other.checks;
        self.produced += other.produced;
        self.producer_replays += other.producer_replays;
        self.producer_replay_checks += other.producer_replay_checks;
        self.producer_cache_hits += other.producer_cache_hits;
        self.producer_cache_overflow += other.producer_cache_overflow;
        self.producer_peak_cache = self.producer_peak_cache.max(other.producer_peak_cache);
        self.hinted += other.hinted;
        self.ordinary += other.ordinary;
        self.false_checks += other.false_checks;
        self.batches += other.batches;
        self.direct += other.direct;
        self.failed_batches += other.failed_batches;
        self.worker_errors += other.worker_errors;
        self.retry_groups += other.retry_groups;
        self.retry_checks += other.retry_checks;
        self.max_retry_jobs = self.max_retry_jobs.max(other.max_retry_jobs);
        self.groups += other.groups;
        self.max_pending = self.max_pending.max(other.max_pending);
        self.worker_cpu_ns += other.worker_cpu_ns;
        self.workers += other.workers;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Baseline,
    Capture,
    Candidate,
    Stream,
    Produce,
    ProduceBatch,
    ProduceReplay,
    Pack,
}

struct Session {
    mode: Mode,
    hints: HashMap<[u8; 32], Vec<u8>>,
    reader: Mutex<Option<codec::Reader>>,
    trace: Mutex<Option<BufWriter<File>>>,
    workers: Mutex<Vec<Worker>>,
    worker_path: PathBuf,
    batch_size: usize,
    minimum: usize,
    group_jobs: usize,
    disabled: AtomicBool,
    stats: Mutex<Stats>,
}

struct Worker {
    child: Child,
    input: Option<BufWriter<ChildStdin>>,
    output: BufReader<ChildStdout>,
}
impl Worker {
    fn start(path: &Path) -> io::Result<Self> {
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("worker stdin"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("worker stdout"))?;
        Ok(Self {
            child,
            input: Some(BufWriter::new(input)),
            output: BufReader::new(output),
        })
    }
    fn batch(&mut self, records: &[[u8; 130]]) -> io::Result<(bool, u64)> {
        let input = self.input.as_mut().unwrap();
        input.write_all(b"B")?;
        input.write_all(&(records.len() as u32).to_le_bytes())?;
        for record in records {
            input.write_all(record)?;
        }
        input.flush()?;
        let mut reply = [0; 9];
        self.output.read_exact(&mut reply)?;
        if reply[0] > 1 {
            return Err(io::Error::other("bad worker verdict"));
        }
        Ok((
            reply[0] == 1,
            u64::from_le_bytes(reply[1..].try_into().unwrap()),
        ))
    }
    fn produce(&mut self, record: &[u8; 130]) -> io::Result<(u8, u64)> {
        let input = self.input.as_mut().unwrap();
        input.write_all(b"P\x01\0\0\0")?;
        input.write_all(record)?;
        input.flush()?;
        let mut response = [0; 9];
        self.output.read_exact(&mut response)?;
        if response[0] > 3 && response[0] != 255 {
            return Err(io::Error::other("producer verdict"));
        }
        Ok((
            response[0],
            u64::from_le_bytes(response[1..].try_into().unwrap()),
        ))
    }
    fn produce_many(&mut self, records: &[[u8; 130]]) -> io::Result<(Vec<u8>, u64)> {
        let input = self.input.as_mut().unwrap();
        input.write_all(b"P")?;
        input.write_all(&(records.len() as u32).to_le_bytes())?;
        for record in records {
            input.write_all(record)?;
        }
        input.flush()?;
        let mut hints = vec![0; records.len()];
        self.output.read_exact(&mut hints)?;
        if hints.iter().any(|h| *h > 3 && *h != 255) {
            return Err(io::Error::other("producer verdict"));
        }
        let mut cpu = [0; 8];
        self.output.read_exact(&mut cpu)?;
        Ok((hints, u64::from_le_bytes(cpu)))
    }
    fn close(mut self) -> io::Result<()> {
        self.input.take();
        if self.child.wait()?.success() {
            Ok(())
        } else {
            Err(io::Error::other("worker exit"))
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.input.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

type TraceFrame = ([u8; 32], Vec<[u8; 130]>);
struct Group {
    mode: Mode,
    hints: &'static [u8],
    token: Token,
    generated: Vec<([u8; 32], Vec<u8>)>,
    // Exact canonical inputs, not a short digest: cached answers cannot alias.
    cache: HashMap<[u8; 129], u8>,
    pending_slots: Vec<(usize, usize)>,
    producer_retry: bool,
    provisional: u64,
    ordinal: usize,
    pending: Vec<[u8; 130]>,
    trace: Vec<TraceFrame>,
    worker: Option<Worker>,
    failed: bool,
    jobs: u64,
    stats: Stats,
}
impl Group {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            hints: &[],
            token: None,
            generated: Vec::new(),
            cache: HashMap::new(),
            pending_slots: Vec::new(),
            producer_retry: false,
            provisional: 0,
            ordinal: 0,
            pending: Vec::new(),
            trace: Vec::new(),
            worker: None,
            failed: false,
            jobs: 0,
            stats: Stats::default(),
        }
    }
    fn worker(&mut self) -> io::Result<&mut Worker> {
        let s = SESSION.get().unwrap();
        if self.worker.is_none() {
            self.worker = s.workers.lock().unwrap().pop();
            if self.worker.is_none() {
                self.stats.workers += 1;
                self.worker = Some(Worker::start(&s.worker_path)?);
            }
        }
        Ok(self.worker.as_mut().unwrap())
    }
    fn produce(&mut self, record: &[u8; 130]) -> Option<u8> {
        if SESSION.get().unwrap().disabled.load(Ordering::Acquire) {
            return None;
        }
        match self.worker().and_then(|w| w.produce(record)) {
            Ok((hint, cpu)) => {
                self.stats.worker_cpu_ns += cpu;
                self.stats.produced += 1;
                Some(hint)
            }
            Err(_) => {
                self.stats.worker_errors += 1;
                self.worker.take();
                SESSION
                    .get()
                    .unwrap()
                    .disabled
                    .store(true, Ordering::Release);
                None
            }
        }
    }
    fn remember(&mut self, record: &[u8; 130], hint: u8) {
        // A malicious Script cannot make memoization grow with history.
        if self.cache.len() < MAX_BATCH {
            self.cache.insert(record[..129].try_into().unwrap(), hint);
            self.stats.producer_peak_cache =
                self.stats.producer_peak_cache.max(self.cache.len() as u64);
        } else {
            self.stats.producer_cache_overflow += 1;
        }
    }
    fn flush_producer(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let records = std::mem::take(&mut self.pending);
        let slots = std::mem::take(&mut self.pending_slots);
        self.stats.max_pending = self.stats.max_pending.max(records.len() as u64);
        if SESSION.get().unwrap().disabled.load(Ordering::Acquire) {
            self.producer_retry = true;
            return;
        }
        match self.worker().and_then(|w| w.produce_many(&records)) {
            Ok((hints, cpu)) => {
                self.stats.produced += hints.len() as u64;
                self.stats.worker_cpu_ns += cpu;
                for ((record, hint), (tx, ordinal)) in records.iter().zip(hints).zip(slots) {
                    self.generated[tx].1[ordinal] = hint;
                    self.remember(record, hint);
                    self.producer_retry |= hint == 255;
                }
            }
            Err(_) => {
                self.stats.worker_errors += 1;
                self.worker.take();
                self.producer_retry = true;
                SESSION
                    .get()
                    .unwrap()
                    .disabled
                    .store(true, Ordering::Release);
            }
        }
    }
    fn flush(&mut self) {
        if self.mode == Mode::ProduceBatch {
            self.flush_producer();
            return;
        }
        if self.pending.is_empty() {
            return;
        }
        let s = SESSION.get().unwrap();
        self.stats.max_pending = self.stats.max_pending.max(self.pending.len() as u64);
        if !self.failed {
            // Small batches use exact individual checks: no child startup/MSM
            // overhead and no trust in the supplied nonce point.
            let valid = if self.pending.len() < s.minimum {
                self.stats.direct += self.pending.len() as u64;
                self.pending.iter().all(ordinary_record)
            } else {
                if self.worker.is_none() {
                    self.worker = s.workers.lock().unwrap().pop();
                    if self.worker.is_none() {
                        self.stats.workers += 1;
                        self.worker = Worker::start(&s.worker_path).ok();
                    }
                }
                self.stats.batches += 1;
                match self
                    .worker
                    .as_mut()
                    .ok_or_else(|| io::Error::other("worker start"))
                    .and_then(|w| w.batch(&self.pending))
                {
                    Ok((valid, cpu)) => {
                        self.stats.worker_cpu_ns += cpu;
                        valid
                    }
                    Err(_) => {
                        self.stats.worker_errors += 1;
                        self.worker.take();
                        false
                    }
                }
            };
            if !valid {
                self.stats.failed_batches += 1;
                self.failed = true;
                s.disabled.store(true, Ordering::Release);
            }
        }
        self.pending.clear();
    }
}

fn ordinary_record(record: &[u8; 130]) -> bool {
    static SECP: OnceLock<secp256k1::Secp256k1<secp256k1::VerifyOnly>> = OnceLock::new();
    let Ok(pk) = secp256k1::PublicKey::from_slice(&record[96..129]) else {
        return false;
    };
    let Ok(sig) = secp256k1::ecdsa::Signature::from_compact(&record[32..96]) else {
        return false;
    };
    let msg = secp256k1::Message::from_digest(record[..32].try_into().unwrap());
    SECP.get_or_init(secp256k1::Secp256k1::verification_only)
        .verify_ecdsa(&msg, &sig, &pk)
        .is_ok()
}

fn load_hints(path: &Path) -> io::Result<(HashMap<[u8; 32], Vec<u8>>, u64)> {
    // Read through a bound as well as checking metadata (file may change).
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_HINT_FILE {
        return Err(io::Error::other("sidecar bound"));
    }
    let mut data = Vec::new();
    file.take(MAX_HINT_FILE + 1).read_to_end(&mut data)?;
    let size = data.len();
    if size as u64 > MAX_HINT_FILE || data.get(..8) != Some(b"AVADVC03") {
        return Err(io::Error::other("sidecar framing"));
    }
    let mut remaining = &data[8..];
    let mut result = HashMap::new();
    while !remaining.is_empty() {
        if remaining.len() < 36 {
            return Err(io::Error::other("truncated frame"));
        }
        let key = remaining[..32].try_into().unwrap();
        let count = u32::from_le_bytes(remaining[32..36].try_into().unwrap()) as usize;
        remaining = &remaining[36..];
        if count == 0 || count > MAX_TX_HINTS || count > remaining.len() || result.len() == 500_000
        {
            return Err(io::Error::other("frame bound"));
        }
        if result.insert(key, remaining[..count].to_vec()).is_some() {
            return Err(io::Error::other("duplicate transaction frame"));
        }
        remaining = &remaining[count..];
    }
    Ok((result, size as u64))
}

pub fn configure(
    mode: &str,
    path: &Path,
    worker: &Path,
    batch_size: usize,
    minimum: usize,
    group_jobs: usize,
) -> io::Result<()> {
    if !(1..=MAX_BATCH).contains(&batch_size)
        || minimum > MAX_BATCH
        || !(1..=1024).contains(&group_jobs)
    {
        return Err(io::Error::other("experiment limits"));
    }
    let mode = match mode {
        "baseline" => Mode::Baseline,
        "capture" => Mode::Capture,
        "candidate" => Mode::Candidate,
        "stream" => Mode::Stream,
        "produce" => Mode::Produce,
        "produce-batch" => Mode::ProduceBatch,
        "pack" => Mode::Pack,
        _ => return Err(io::Error::other("mode")),
    };
    let mut stats = Stats::default();
    let mut hints = HashMap::new();
    if matches!(mode, Mode::Candidate | Mode::Pack) {
        match load_hints(path) {
            Ok((map, size)) => {
                hints = map;
                stats.hints_bytes = size;
            }
            Err(_) => stats.sidecar_rejected = true,
        }
    }
    let reader = if mode == Mode::Stream {
        stats.hints_bytes = std::fs::metadata(path).map_or(0, |m| m.len());
        match codec::Reader::open(path) {
            Ok(reader) => Some(reader),
            Err(_) => {
                stats.sidecar_rejected = true;
                None
            }
        }
    } else {
        None
    };
    let trace = if matches!(mode, Mode::Capture | Mode::Produce | Mode::ProduceBatch) {
        let mut file = BufWriter::new(File::create(path)?);
        file.write_all(if mode == Mode::Capture {
            b"AVTRACE3"
        } else {
            b"AVADVC03"
        })?;
        Some(file)
    } else {
        None
    };
    SESSION
        .set(Session {
            mode,
            hints,
            reader: Mutex::new(reader),
            trace: Mutex::new(trace),
            workers: Mutex::new(Vec::new()),
            worker_path: worker.to_path_buf(),
            batch_size,
            minimum,
            group_jobs,
            disabled: AtomicBool::new(stats.sidecar_rejected),
            stats: Mutex::new(stats),
        })
        .map_err(|_| io::Error::other("one session per process"))
}

/// The ordinary arm retains the existing pool's one-job scheduling.
pub fn group_capacity() -> usize {
    SESSION
        .get()
        .filter(|s| {
            matches!(
                s.mode,
                Mode::Candidate | Mode::Stream | Mode::Produce | Mode::ProduceBatch
            ) && !s.disabled.load(Ordering::Acquire)
        })
        .map_or(1, |s| s.group_jobs)
}

/// Run a bounded group of immutable transactions. The caller owns them until
/// this function returns, and must not complete BlockCheck earlier.
pub fn group<T>(estimated_checks: usize, mut work: impl FnMut() -> (T, bool)) -> T {
    let Some(session) = SESSION.get() else {
        return work().0;
    };
    let mut mode = if (session.disabled.load(Ordering::Acquire)
        && !matches!(session.mode, Mode::Produce | Mode::ProduceBatch))
        || (matches!(session.mode, Mode::Candidate | Mode::Stream)
            && estimated_checks < session.minimum)
        || session.mode == Mode::Pack
    {
        Mode::Baseline
    } else {
        session.mode
    };
    if mode == Mode::ProduceBatch && session.disabled.load(Ordering::Acquire) {
        mode = Mode::Produce;
    }
    GROUP.with_borrow_mut(|slot| {
        assert!(slot.is_none());
        *slot = Some(Group::new(mode));
    });
    let (mut result, script_error) = work();
    let mut group = GROUP.with_borrow_mut(|slot| slot.take().unwrap());
    group.flush();
    if group.mode == Mode::ProduceBatch
        && (group.producer_retry || (script_error && group.provisional > 0))
    {
        let mut retry = Group::new(Mode::ProduceReplay);
        retry.cache = std::mem::take(&mut group.cache);
        retry.worker = group.worker.take();
        GROUP.with_borrow_mut(|slot| *slot = Some(retry));
        result = work().0;
        let mut exact = GROUP.with_borrow_mut(|slot| slot.take().unwrap());
        // Final Script attempt/false counts describe the actual execution.
        // Producer work, including abandoned branches, remains fully charged.
        let checks = exact.stats.checks;
        let false_checks = exact.stats.false_checks;
        exact.stats.producer_replays += 1;
        exact.stats.producer_replay_checks += checks;
        exact.stats.add(&group.stats);
        exact.stats.checks = checks;
        exact.stats.false_checks = false_checks;
        group = exact;
    }
    if group.failed || (script_error && group.stats.hinted > 0) {
        session.disabled.store(true, Ordering::Release);
        GROUP.with_borrow_mut(|slot| *slot = Some(Group::new(Mode::Baseline)));
        result = work().0;
        let ordinary = GROUP.with_borrow_mut(|slot| slot.take().unwrap());
        group.stats.retry_groups += 1;
        group.stats.retry_checks += ordinary.stats.checks;
        group.stats.max_retry_jobs = group.jobs;
        // First-pass and retry counts remain separate; CPU includes both.
    }
    if let Some(worker) = group.worker {
        session.workers.lock().unwrap().push(worker);
    }
    if group.mode == Mode::Capture {
        let mut guard = session.trace.lock().unwrap();
        let writer = guard.as_mut().unwrap();
        for (key, records) in group.trace {
            if records.is_empty() {
                continue;
            }
            assert!(records.len() <= MAX_TX_HINTS);
            writer.write_all(&key).unwrap();
            writer
                .write_all(&(records.len() as u32).to_le_bytes())
                .unwrap();
            for record in records {
                writer.write_all(&record).unwrap();
            }
        }
    }
    if matches!(
        group.mode,
        Mode::Produce | Mode::ProduceBatch | Mode::ProduceReplay
    ) {
        let mut guard = session.trace.lock().unwrap();
        let writer = guard.as_mut().unwrap();
        for (key, hints) in group.generated {
            if hints.is_empty() {
                continue;
            }
            if hints.len() > MAX_TX_HINTS {
                continue;
            }
            writer.write_all(&key).unwrap();
            writer
                .write_all(&(hints.len() as u32).to_le_bytes())
                .unwrap();
            writer.write_all(&hints).unwrap();
        }
    }
    group.stats.groups += 1;
    session.stats.lock().unwrap().add(&group.stats);
    result
}

pub fn transaction(
    tx: &Transaction,
    mut ordinary: impl FnMut() -> Result<(), ScriptError>,
) -> Result<(), ScriptError> {
    if SESSION.get().is_none() {
        return ordinary();
    }
    let mut run = || {
        GROUP.with_borrow_mut(|slot| {
            let group = slot.as_mut().unwrap();
            group.jobs += 1;
            group.ordinal = 0;
            if group.mode != Mode::Baseline {
                let key = if group.mode == Mode::Stream {
                    [0; 32]
                } else {
                    *tx.wtxid().as_bytes()
                };
                if group.mode == Mode::Capture {
                    group.trace.push((key, Vec::new()));
                }
                if matches!(
                    group.mode,
                    Mode::Produce | Mode::ProduceBatch | Mode::ProduceReplay
                ) {
                    group.generated.push((key, Vec::new()));
                }
                if group.mode == Mode::Stream {
                    group.token = TOKEN.with_borrow(Clone::clone);
                }
                group.hints = SESSION
                    .get()
                    .unwrap()
                    .hints
                    .get(&key)
                    .map_or(&[], Vec::as_slice);
            }
        });
        ordinary()
    };
    if GROUP.with_borrow(|slot| slot.is_some()) {
        run()
    } else {
        group(tx.inputs.len(), || {
            let result = run();
            let error = result.is_err();
            (result, error)
        })
    }
}

pub fn verify(sig: &[u8], pubkey: &[u8], msg: &[u8; 32], ordinary: impl FnOnce() -> bool) -> bool {
    GROUP.with_borrow_mut(|slot| {
        let Some(group) = slot.as_mut() else {
            return ordinary();
        };
        group.stats.checks += 1;
        let hint = if group.mode == Mode::Stream {
            group
                .token
                .as_ref()
                .and_then(|(frame, index)| frame.hints.get(*index))
                .and_then(|hints| hints.get(group.ordinal))
                .copied()
                .unwrap_or(255)
        } else {
            group.hints.get(group.ordinal).copied().unwrap_or(255)
        };
        group.ordinal += 1;
        if group.mode == Mode::ProduceBatch {
            let tx = group.generated.len() - 1;
            let ordinal = group.generated[tx].1.len();
            group.generated[tx].1.push(255);
            let Some(record) = canonical(sig, pubkey, msg) else {
                group.stats.ordinary += 1;
                let result = ordinary();
                group.stats.false_checks += u64::from(!result);
                return result;
            };
            if let Some(&hint) = group
                .cache
                .get::<[u8; 129]>(&record[..129].try_into().unwrap())
            {
                group.stats.producer_cache_hits += 1;
                group.generated[tx].1[ordinal] = hint;
                group.stats.false_checks += u64::from(hint == 255);
                return hint < 4;
            }
            group.provisional += 1;
            group.pending.push(record);
            group.pending_slots.push((tx, ordinal));
            if group.pending.len() == SESSION.get().unwrap().batch_size {
                group.flush();
            }
            return true;
        }
        if matches!(group.mode, Mode::Produce | Mode::ProduceReplay) {
            let produced = canonical(sig, pubkey, msg).and_then(|record| {
                if group.mode == Mode::ProduceReplay {
                    if let Some(&hint) = group
                        .cache
                        .get::<[u8; 129]>(&record[..129].try_into().unwrap())
                    {
                        group.stats.producer_cache_hits += 1;
                        return Some(hint);
                    }
                }
                let hint = group.produce(&record)?;
                if group.mode == Mode::ProduceReplay {
                    group.remember(&record, hint);
                }
                Some(hint)
            });
            let result = match produced {
                Some(hint) => hint < 4,
                None => {
                    group.stats.ordinary += 1;
                    ordinary()
                }
            };
            // Unknown/failed production is conservative advice, even when
            // ordinary verification returns true; recipient verifies it again.
            group
                .generated
                .last_mut()
                .unwrap()
                .1
                .push(produced.unwrap_or(255));
            group.stats.false_checks += u64::from(!result);
            return result;
        }
        if group.mode == Mode::Capture {
            let result = ordinary();
            let mut record = canonical(sig, pubkey, msg).unwrap_or([0; 130]);
            record[129] = u8::from(result);
            group.trace.last_mut().unwrap().1.push(record);
            group.stats.ordinary += 1;
            group.stats.false_checks += u64::from(!result);
            return result;
        }
        if matches!(group.mode, Mode::Candidate | Mode::Stream)
            && !group.failed
            && hint < 4
            && !SESSION.get().unwrap().disabled.load(Ordering::Acquire)
        {
            if let Some(mut record) = canonical(sig, pubkey, msg) {
                record[129] = hint;
                group.pending.push(record);
                group.stats.hinted += 1;
                if group.pending.len() == SESSION.get().unwrap().batch_size {
                    group.flush();
                }
                return true;
            }
        }
        group.stats.ordinary += 1;
        let result = ordinary();
        group.stats.false_checks += u64::from(!result);
        result
    })
}

fn canonical(sig: &[u8], pubkey: &[u8], msg: &[u8; 32]) -> Option<[u8; 130]> {
    let pk = secp256k1::PublicKey::from_slice(pubkey).ok()?;
    let mut sig = secp256k1::ecdsa::Signature::from_der_lax(sig).ok()?;
    sig.normalize_s();
    let mut record = [0; 130];
    record[..32].copy_from_slice(msg);
    record[32..96].copy_from_slice(&sig.serialize_compact());
    record[96..129].copy_from_slice(&pk.serialize());
    Some(record)
}

/// Caller must drain/join all Script jobs before finishing. Waiting for every
/// child here includes native verification CPU in the parent's resource totals.
pub fn finish() -> io::Result<Stats> {
    let s = SESSION.get().unwrap();
    if let Some(mut writer) = s.trace.lock().unwrap().take() {
        writer.flush()?;
    }
    let workers = std::mem::take(&mut *s.workers.lock().unwrap());
    for worker in workers {
        worker.close()?;
    }
    let mut stats = s.stats.lock().unwrap().clone();
    stats.disabled = s.disabled.load(Ordering::Acquire);
    if let Some(reader) = s.reader.lock().unwrap().as_ref() {
        stats.stream_bytes = reader.stats.bytes;
        stats.stream_frames = reader.stats.frames;
        stats.stream_missed = reader.stats.missed;
        stats.stream_rejected = reader.stats.rejected;
    }
    (stats.peak_frames, stats.peak_hint_bytes) = codec::peaks();
    Ok(stats)
}

/// Attach advice to the actual local block and transaction positions.
pub fn begin_block(hash: &[u8; 32], transactions: usize) -> Option<Arc<codec::Frame>> {
    let s = SESSION.get()?;
    if s.mode != Mode::Stream || s.disabled.load(Ordering::Acquire) {
        return None;
    }
    s.reader.lock().unwrap().as_mut()?.block(hash, transactions)
}
pub fn token(frame: &Option<Arc<codec::Frame>>, index: usize) -> Token {
    codec::token(frame, index)
}
pub fn with_token<T>(token: &Token, work: impl FnOnce() -> T) -> T {
    struct Restore(Token);
    impl Drop for Restore {
        fn drop(&mut self) {
            TOKEN.with_borrow_mut(|t| *t = self.0.take());
        }
    }
    let previous = TOKEN.with_borrow_mut(|t| std::mem::replace(t, token.clone()));
    let _guard = Restore(previous);
    work()
}
pub fn pack_transactions(
    writer: &mut impl Write,
    hash: &[u8; 32],
    txs: &[Transaction],
) -> io::Result<()> {
    let s = SESSION.get().unwrap();
    if s.mode != Mode::Pack || s.stats.lock().unwrap().sidecar_rejected {
        return Err(io::Error::other("pack input"));
    }
    let hints: Vec<_> = txs
        .iter()
        .map(|tx| {
            s.hints
                .get(tx.wtxid().as_bytes())
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    codec::write_frame(writer, hash, &hints)
}

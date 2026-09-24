//! Isolated, bounded, parallel nonce-advice experiment. No live-node interface.
//! A pool job completes only AFTER its group's equations pass or ordinary
//! Script replay supplies the verdict. Advice never supplies trusted false.
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use crate::interpreter::ScriptError;
use crate::transaction::Transaction;

const MAX_BATCH: usize = 8192;
const MAX_HINT_FILE: u64 = 32 << 20;
const MAX_TX_HINTS: usize = 80_000;
static SESSION: OnceLock<Session> = OnceLock::new();
thread_local! { static GROUP: RefCell<Option<Group>> = const { RefCell::new(None) }; }

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub checks: u64,
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
}

struct Session {
    mode: Mode,
    hints: HashMap<[u8; 32], Vec<u8>>,
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
            ordinal: 0,
            pending: Vec::new(),
            trace: Vec::new(),
            worker: None,
            failed: false,
            jobs: 0,
            stats: Stats::default(),
        }
    }
    fn flush(&mut self) {
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
        _ => return Err(io::Error::other("mode")),
    };
    let mut stats = Stats::default();
    let mut hints = HashMap::new();
    if mode == Mode::Candidate {
        match load_hints(path) {
            Ok((map, size)) => {
                hints = map;
                stats.hints_bytes = size;
            }
            Err(_) => stats.sidecar_rejected = true,
        }
    }
    let trace = if mode == Mode::Capture {
        let mut file = BufWriter::new(File::create(path)?);
        file.write_all(b"AVTRACE3")?;
        Some(file)
    } else {
        None
    };
    SESSION
        .set(Session {
            mode,
            hints,
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
        .filter(|s| s.mode == Mode::Candidate && !s.disabled.load(Ordering::Acquire))
        .map_or(1, |s| s.group_jobs)
}

/// Run a bounded group of immutable transactions. The caller owns them until
/// this function returns, and must not complete BlockCheck earlier.
pub fn group<T>(mut work: impl FnMut() -> (T, bool)) -> T {
    let Some(session) = SESSION.get() else {
        return work().0;
    };
    let mode = if session.disabled.load(Ordering::Acquire) {
        Mode::Baseline
    } else {
        session.mode
    };
    GROUP.with_borrow_mut(|slot| {
        assert!(slot.is_none());
        *slot = Some(Group::new(mode));
    });
    let (mut result, script_error) = work();
    let mut group = GROUP.with_borrow_mut(|slot| slot.take().unwrap());
    group.flush();
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
                let key = *tx.wtxid().as_bytes();
                if group.mode == Mode::Capture {
                    group.trace.push((key, Vec::new()));
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
        group(|| {
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
        let hint = group.hints.get(group.ordinal).copied().unwrap_or(255);
        group.ordinal += 1;
        if group.mode == Mode::Capture {
            let result = ordinary();
            let mut record = canonical(sig, pubkey, msg).unwrap_or([0; 130]);
            record[129] = u8::from(result);
            group.trace.last_mut().unwrap().1.push(record);
            group.stats.ordinary += 1;
            group.stats.false_checks += u64::from(!result);
            return result;
        }
        if group.mode == Mode::Candidate
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
    Ok(stats)
}

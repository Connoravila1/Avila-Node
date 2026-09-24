//! Lab-only hook copied into an isolated build, never the production crate.
//! A candidate replay is provisional until `finish()` succeeds. Any failed
//! batch or speculative Script error requires discarding the whole replay and
//! repeating it with ordinary checks. No provisional state is published.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub checks: u64,
    pub hinted: u64,
    pub ordinary: u64,
    pub false_checks: u64,
    pub uncompressed: u64,
    pub hybrid: u64,
    pub high_s: u64,
    pub batches: u64,
    pub worker_cpu_ns: u64,
    pub failed: bool,
    pub hints_bytes: usize,
}

enum Mode {
    Baseline,
    Capture(BufWriter<File>),
    Candidate,
}

struct Worker {
    child: Child,
    input: BufWriter<ChildStdin>,
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
            input: BufWriter::new(input),
            output: BufReader::new(output),
        })
    }

    fn batch(&mut self, records: &[[u8; 130]]) -> io::Result<(bool, u64)> {
        assert!(!records.is_empty() && records.len() <= 8192);
        self.input.write_all(b"B")?;
        self.input
            .write_all(&(records.len() as u32).to_le_bytes())?;
        for record in records {
            self.input.write_all(record)?;
        }
        self.input.flush()?;
        let mut response = [0u8; 9];
        self.output.read_exact(&mut response)?;
        if response[0] > 1 {
            return Err(io::Error::other("bad worker verdict"));
        }
        Ok((
            response[0] == 1,
            u64::from_le_bytes(response[1..].try_into().unwrap()),
        ))
    }

    fn close(self) -> io::Result<()> {
        let Self {
            mut child,
            input,
            output,
        } = self;
        drop(input);
        drop(output);
        if !child.wait()?.success() {
            return Err(io::Error::other("worker failed"));
        }
        Ok(())
    }
}

struct Session {
    mode: Mode,
    hints: Vec<u8>,
    pending: Vec<[u8; 130]>,
    batch_size: usize,
    worker: Option<Worker>,
    stats: Stats,
}

impl Session {
    fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        if !self.stats.failed {
            self.stats.batches += 1;
            match self.worker.as_mut().unwrap().batch(&self.pending) {
                Ok((valid, cpu)) => {
                    self.stats.worker_cpu_ns += cpu;
                    self.stats.failed |= !valid;
                }
                Err(_) => self.stats.failed = true,
            }
        }
        self.pending.clear();
    }
}

pub fn configure(mode: &str, path: &Path, worker: &Path, batch_size: usize) -> io::Result<()> {
    if !(1..=8192).contains(&batch_size) {
        return Err(io::Error::other("batch size"));
    }
    let mut session = Session {
        mode: Mode::Baseline,
        hints: Vec::new(),
        pending: Vec::with_capacity(batch_size),
        batch_size,
        worker: None,
        stats: Stats::default(),
    };
    match mode {
        "baseline" => {}
        "capture" => session.mode = Mode::Capture(BufWriter::new(File::create(path)?)),
        "candidate" => {
            if std::fs::metadata(path)?.len() > 32 << 20 {
                return Err(io::Error::other("hint file exceeds 32 MiB bound"));
            }
            session.hints = std::fs::read(path)?;
            session.stats.hints_bytes = session.hints.len();
            session.worker = Some(Worker::start(worker)?);
            session.mode = Mode::Candidate;
        }
        _ => return Err(io::Error::other("unknown experiment mode")),
    }
    let mut state = SESSION.lock().unwrap();
    assert!(state.is_none(), "finish previous experiment first");
    *state = Some(session);
    Ok(())
}

fn canonical(sig: &[u8], pubkey: &[u8], msg: &[u8; 32], stats: &mut Stats) -> Option<[u8; 130]> {
    let pk = secp256k1::PublicKey::from_slice(pubkey).ok()?;
    let mut signature = secp256k1::ecdsa::Signature::from_der_lax(sig).ok()?;
    let original = signature.serialize_compact();
    signature.normalize_s();
    let normalized = signature.serialize_compact();
    stats.high_s += u64::from(original != normalized);
    let mut record = [0u8; 130];
    record[..32].copy_from_slice(msg);
    record[32..96].copy_from_slice(&normalized);
    record[96..129].copy_from_slice(&pk.serialize());
    Some(record)
}

/// Returns provisional true only when a locally computed signature equation
/// has been queued for checking. Sentinel/missing hints use ordinary checks;
/// a helper's claimed false is NEVER accepted without local verification.
pub fn verify(sig: &[u8], pubkey: &[u8], msg: &[u8; 32], ordinary: impl FnOnce() -> bool) -> bool {
    let mut state = SESSION.lock().unwrap();
    let Some(s) = state.as_mut() else {
        return ordinary();
    };
    let index = s.stats.checks as usize;
    s.stats.checks += 1;
    s.stats.uncompressed += u64::from(pubkey.len() == 65);
    s.stats.hybrid += u64::from(matches!(pubkey.first(), Some(6 | 7)));
    if matches!(s.mode, Mode::Baseline) {
        s.stats.ordinary += 1;
        let result = ordinary();
        s.stats.false_checks += u64::from(!result);
        return result;
    }
    let record = canonical(sig, pubkey, msg, &mut s.stats);
    if let Mode::Capture(writer) = &mut s.mode {
        let result = ordinary();
        let mut record = record.unwrap_or([0; 130]);
        record[129] = u8::from(result);
        writer
            .write_all(&record)
            .expect("write public experimental trace");
        s.stats.ordinary += 1;
        s.stats.false_checks += u64::from(!result);
        return result;
    }
    let hint = s.hints.get(index).copied().unwrap_or(255);
    if hint < 4 && !s.stats.failed {
        if let Some(mut record) = record {
            record[129] = hint;
            s.pending.push(record);
            s.stats.hinted += 1;
            if s.pending.len() == s.batch_size {
                s.flush();
            }
            // Even a just-failed batch is provisional: caller discards/replays.
            return true;
        }
    }
    s.stats.ordinary += 1;
    let result = ordinary();
    s.stats.false_checks += u64::from(!result);
    result
}

pub fn finish() -> io::Result<Stats> {
    let mut s = SESSION
        .lock()
        .unwrap()
        .take()
        .expect("configured experiment");
    s.flush();
    if let Mode::Capture(writer) = &mut s.mode {
        writer.flush()?;
    }
    if let Some(worker) = s.worker {
        s.stats.failed |= worker.close().is_err();
    }
    Ok(s.stats)
}

/// Decode Core's CBlockUndo using the existing compact Coin primitives.
/// Undo data is supplied prestate for the isolated historical script workload.
pub fn undo_outputs(
    mut data: &[u8],
    block: &crate::block::Block,
) -> io::Result<Vec<Vec<crate::transaction::TxOut>>> {
    use crate::transaction::TxOut;
    use crate::utxo_snapshot::{decompress_amount, decompress_script, read_varint};
    fn count(data: &mut &[u8]) -> io::Result<u64> {
        let mut first = [0u8; 1];
        data.read_exact(&mut first)?;
        let mut bytes = [0u8; 8];
        let size = match first[0] {
            253 => 2,
            254 => 4,
            255 => 8,
            n => return Ok(u64::from(n)),
        };
        data.read_exact(&mut bytes[..size])?;
        let value = u64::from_le_bytes(bytes);
        let minimum = match size {
            2 => 253,
            4 => 65536,
            _ => 1u64 << 32,
        };
        if value < minimum {
            return Err(io::Error::other("noncanonical count"));
        }
        Ok(value)
    }
    if count(&mut data)? as usize != block.transactions.len() - 1 {
        return Err(io::Error::other("undo transaction count"));
    }
    let mut result = Vec::new();
    for tx in &block.transactions[1..] {
        if count(&mut data)? as usize != tx.inputs.len() {
            return Err(io::Error::other("undo input count"));
        }
        let mut outputs = Vec::new();
        for _ in &tx.inputs {
            let code = read_varint(&mut data)?;
            if code >> 1 != 0 {
                let _ = read_varint(&mut data)?;
            }
            let amount = decompress_amount(read_varint(&mut data)?);
            if amount > 2_100_000_000_000_000 {
                return Err(io::Error::other("undo amount"));
            }
            let size = read_varint(&mut data)?;
            if size > 10_006 {
                return Err(io::Error::other("undo script length"));
            }
            outputs.push(TxOut {
                value: amount as i64,
                script_pubkey: decompress_script(&mut data, size)?,
            });
        }
        result.push(outputs);
    }
    if !data.is_empty() {
        return Err(io::Error::other("trailing undo bytes"));
    }
    Ok(result)
}

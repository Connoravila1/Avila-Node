use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

/// Fixed-size events keep retention bounded in bytes as well as entry count.
/// Future events carrying data must add payload limits and redaction tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeEvent {
    ConfigurationLoaded,
    StartupBlocked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EventRecord {
    pub sequence: u64,
    pub event: NodeEvent,
}

/// Process-local diagnostic history, NOT a durable consensus journal.
#[derive(Debug)]
pub struct EventJournal {
    capacity: NonZeroUsize,
    next_sequence: u64,
    entries: VecDeque<EventRecord>,
}

impl EventJournal {
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            next_sequence: 0,
            entries: VecDeque::new(),
        }
    }

    pub fn push(&mut self, event: NodeEvent) -> Result<(), JournalError> {
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        if self.entries.len() == self.capacity.get() {
            self.entries.pop_front();
        }
        self.entries.push_back(EventRecord { sequence, event });
        self.next_sequence = next_sequence;
        Ok(())
    }

    pub fn entries(&self) -> impl DoubleEndedIterator<Item = &EventRecord> {
        self.entries.iter()
    }
}

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("event sequence exhausted; refusing to reuse an event identifier")]
    SequenceExhausted,
}

/// Filename inside the network data dir — `tail -f`-able, `jq`-able.
pub const EVENTS_FILENAME: &str = "events.ndjson";
/// Rotate at this size to `events.ndjson.1`; total footprint stays
/// bounded at ~8 MiB.
pub const MAX_STREAM_BYTES: u64 = 4 << 20;

/// The append-only NDJSON event plane — the "stream law" artifact:
/// `avila-node events --follow`, the GUI, and external plumbing all
/// read the same wire. Rotation happens between whole lines, so a
/// follower never sees a torn record.
pub struct EventStream {
    file: File,
    path: PathBuf,
    seq: u64,
    written: u64,
}

impl EventStream {
    /// Open (or create) `<dir>/events.ndjson` for append. `seq`
    /// continues past the previous run's last event — followers dedup
    /// on it, so it must be monotonic across restarts and rotations.
    pub fn open(dir: &Path) -> io::Result<Self> {
        let path = dir.join(EVENTS_FILENAME);
        let written = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut seq = 0;
        if written > 0
            && let Ok(mut f) = File::open(&path)
        {
            let tail = written.min(8192);
            if f.seek(SeekFrom::End(-(tail as i64))).is_ok() {
                let mut buf = Vec::new();
                if f.take(tail).read_to_end(&mut buf).is_ok() {
                    for line in String::from_utf8_lossy(&buf).lines().rev() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(line)
                            && let Some(s) = v.get("seq").and_then(|s| s.as_u64())
                        {
                            seq = s + 1;
                            break;
                        }
                    }
                }
            }
        }
        let file = File::options().create(true).append(true).open(&path)?;
        Ok(Self {
            file,
            path,
            seq,
            written,
        })
    }

    /// Emit one line: `{"seq", "time", "kind", ...fields}`. Write
    /// errors surface to the caller — the stream is diagnostic, the
    /// caller decides how loud a broken sink is.
    pub fn emit(&mut self, kind: &str, fields: serde_json::Value) -> io::Result<()> {
        let mut line = serde_json::json!({
            "seq": self.seq,
            "time": crate::time::system_time(),
            "kind": kind,
        });
        if let (serde_json::Value::Object(obj), serde_json::Value::Object(f)) = (&mut line, fields)
        {
            obj.extend(f);
        }
        let mut bytes = serde_json::to_vec(&line).unwrap_or_default();
        bytes.push(b'\n');
        if self.written + bytes.len() as u64 > MAX_STREAM_BYTES {
            self.file.sync_data()?;
            let rotated = self.path.with_extension("ndjson.1");
            let _ = std::fs::rename(&self.path, &rotated);
            self.file = File::create(&self.path)?;
            self.written = 0;
        }
        self.file.write_all(&bytes)?;
        self.seq += 1;
        self.written += bytes.len() as u64;
        Ok(())
    }
}

/// Map a `NetEvent` to `(kind, fields)` for the wire. The p2p crate
/// stays free of serialization concerns — the event schema is a node
/// artifact, so a variant gaining a field lands here.
pub fn net_event_json(event: &avila_p2p::manager::NetEvent) -> (&'static str, serde_json::Value) {
    use avila_p2p::manager::NetEvent::*;
    match event {
        Connected { peer, info } => (
            "peer_connected",
            serde_json::json!({
                "peer": peer,
                "user_agent": info.user_agent,
                "services": info.services,
                "protocol_version": info.version,
                "start_height": info.start_height,
            }),
        ),
        Disconnected { peer, reason } => (
            "peer_disconnected",
            serde_json::json!({"peer": peer, "reason": format!("{reason:?}")}),
        ),
        TipAdvanced(height) => ("tip_advanced", serde_json::json!({"height": height})),
        EclipseSuspected(signals) => (
            "eclipse_suspected",
            serde_json::json!({"signals": signals.iter().map(|s| format!("{s:?}")).collect::<Vec<_>>()}),
        ),
        ProxyUnreachable => ("proxy_unreachable", serde_json::json!({})),
        V2Downgraded { addr } => (
            "v2_downgraded",
            serde_json::json!({"addr": addr.to_string()}),
        ),
        CpuThrottled { peer, rate_ns } => (
            "cpu_throttled",
            serde_json::json!({"peer": peer, "rate_ns": rate_ns}),
        ),
        Announced { peer, missing } => (
            "blocks_announced",
            serde_json::json!({"peer": peer, "missing": missing.len()}),
        ),
        ReconDivergence {
            peer,
            rounds,
            their_misses,
            our_misses,
        } => (
            "recon_divergence",
            serde_json::json!({
                "peer": peer,
                "rounds": rounds,
                "their_misses": their_misses,
                "our_misses": our_misses,
            }),
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn retains_only_the_newest_entries_in_order() {
        let mut journal = EventJournal::new(NonZeroUsize::new(2).unwrap());
        for _ in 0..5 {
            journal.push(NodeEvent::ConfigurationLoaded).unwrap();
        }
        let sequences: Vec<_> = journal.entries().map(|entry| entry.sequence).collect();
        assert_eq!(sequences, vec![3, 4]);
    }

    #[test]
    fn single_entry_capacity_is_supported() {
        let mut journal = EventJournal::new(NonZeroUsize::MIN);
        journal.push(NodeEvent::ConfigurationLoaded).unwrap();
        journal.push(NodeEvent::StartupBlocked).unwrap();
        assert_eq!(journal.entries().count(), 1);
        assert_eq!(
            journal.entries().next().unwrap().event,
            NodeEvent::StartupBlocked
        );
    }

    #[test]
    fn sequence_exhaustion_does_not_mutate_history() {
        let mut journal = EventJournal::new(NonZeroUsize::MIN);
        journal.push(NodeEvent::ConfigurationLoaded).unwrap();
        journal.next_sequence = u64::MAX;
        assert!(journal.push(NodeEvent::StartupBlocked).is_err());
        assert_eq!(journal.entries().next().unwrap().sequence, 0);
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("avila-stream-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn stream_lines_parse_and_seq_survives_reopen() {
        let dir = tmpdir("seq");
        {
            let mut s = EventStream::open(&dir).unwrap();
            s.emit("run_started", serde_json::json!({})).unwrap();
            s.emit("tip_advanced", serde_json::json!({"height": 5}))
                .unwrap();
        }
        {
            let mut s = EventStream::open(&dir).unwrap();
            s.emit("run_stopped", serde_json::json!({})).unwrap();
        }
        let text = std::fs::read_to_string(dir.join(EVENTS_FILENAME)).unwrap();
        let lines: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0]["kind"], "run_started");
        assert_eq!(lines[1]["height"], 5);
        assert_eq!(lines[2]["kind"], "run_stopped");
        assert_eq!(
            lines
                .iter()
                .map(|l| l["seq"].as_u64().unwrap())
                .collect::<Vec<_>>(),
            vec![0, 1, 2],
            "seq must stay monotonic across reopen"
        );
        assert!(lines.iter().all(|l| l["time"].is_i64()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotation_bounds_the_stream_file() {
        let dir = tmpdir("rotate");
        let path = dir.join(EVENTS_FILENAME);
        let mut s = EventStream::open(&dir).unwrap();
        // One 64 KiB line per emit — a fixed count, not a size poll,
        // since the file resets after each rotation.
        let pad = "x".repeat(64 * 1024);
        for _ in 0..(MAX_STREAM_BYTES / 65536 + 2) {
            s.emit("pad", serde_json::json!({"p": pad})).unwrap();
        }
        drop(s);
        assert!(dir.join("events.ndjson.1").exists());
        assert!(std::fs::metadata(&path).unwrap().len() < MAX_STREAM_BYTES);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn net_event_maps_to_wire_shapes() {
        let (kind, f) = net_event_json(&avila_p2p::manager::NetEvent::TipAdvanced(42));
        assert_eq!(kind, "tip_advanced");
        assert_eq!(f["height"], 42);
        let (kind, f) = net_event_json(&avila_p2p::manager::NetEvent::Connected {
            peer: 3,
            info: Box::new(avila_p2p::session::PeerInfo {
                version: 70016,
                services: 1033,
                start_height: 880_000,
                user_agent: "/Satoshi:28.0.0.1/".into(),
                relay: true,
                wtxid_relay: true,
                addrv2: true,
                recon: None,
                utxproof: false,
            }),
        });
        assert_eq!(kind, "peer_connected");
        assert_eq!(f["peer"], 3);
        assert_eq!(f["user_agent"], "/Satoshi:28.0.0.1/");
        assert_eq!(f["protocol_version"], 70016);
    }
}

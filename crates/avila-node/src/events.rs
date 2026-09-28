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
        // seq continues past the last emitted line — from this file,
        // or after a rotation, from the rotated tail's last line. The
        // contract is monotone across restarts AND rotations.
        let mut seq = 0;
        for candidate in [&path, &path.with_extension("ndjson.1")] {
            let size = std::fs::metadata(candidate).map(|m| m.len()).unwrap_or(0);
            if size == 0 {
                continue;
            }
            if let Ok(mut f) = File::open(candidate) {
                let tail = size.min(8192);
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
            if seq > 0 {
                break;
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

/// A tailing reader for `events.ndjson` — the consumption half of the
/// stream law. Followers (GUI, external plumbing) keep a byte cursor;
/// rotation/truncation reset it, malformed lines are skipped, `seq`
/// dedups replays. Absent file = idle, not an error.
#[derive(Debug)]
pub struct EventTail {
    path: PathBuf,
    offset: u64,
    /// High-water `seq` — lines at-or-below it are replays (rotation
    /// restarted the file with history intact elsewhere).
    last_seq: Option<u64>,
}

impl EventTail {
    /// Follow `<dir>/events.ndjson` from the current end — existing
    /// history is left to `--follow` tooling; a tail sees new events.
    #[must_use]
    pub fn follow(path: PathBuf) -> Self {
        let offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Self {
            path,
            offset,
            last_seq: None,
        }
    }

    /// Read new events since the cursor, capped at `max` lines —
    /// a follower on a busy node catches up over frames instead of
    /// stalling the caller. Rotation or truncation reopens the file.
    pub fn read_new(&mut self, max: usize) -> Vec<serde_json::Value> {
        let Ok(mut f) = File::open(&self.path) else {
            return Vec::new();
        };
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            // Truncated or rotated away — start the fresh file over.
            self.offset = 0;
        }
        if f.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut buf = Vec::new();
        let mut f = f.take((max * 8192) as u64 + 8192);
        if f.read_to_end(&mut buf).is_err() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(&buf);
        // The last line may be torn — a writer mid-append hasn't
        // terminated it. Only consume newline-terminated lines; the
        // torn tail stays for the next pass to read whole.
        let complete = text.ends_with('\n');
        let mut out = Vec::new();
        let mut consumed: u64 = 0;
        let n_lines = text.lines().count();
        for (i, line) in text.lines().enumerate() {
            if i >= max || (i == n_lines - 1 && !complete) {
                break;
            }
            consumed += line.len() as u64 + 1;
            if line.is_empty() {
                continue;
            }
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let seq = v.get("seq").and_then(|s| s.as_u64());
            if let (Some(s), Some(hi)) = (seq, self.last_seq)
                && s <= hi
            {
                continue;
            }
            if let Some(s) = seq {
                self.last_seq = Some(self.last_seq.map_or(s, |hi| hi.max(s)));
            }
            out.push(v);
        }
        self.offset += consumed;
        out
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
        CompactReceived {
            peer,
            block,
            short_ids,
        } => (
            "compact_received",
            serde_json::json!({
                "peer": peer,
                "block": block.to_string(),
                "short_ids": short_ids,
            }),
        ),
        CompactHit { peer, block } => (
            "compact_hit",
            serde_json::json!({
                "peer": peer,
                "block": block.to_string(),
            }),
        ),
        CompactPatchRequest {
            peer,
            block,
            missing,
        } => (
            "compact_patch_request",
            serde_json::json!({
                "peer": peer,
                "block": block.to_string(),
                "missing": missing,
            }),
        ),
        CompactFallback { peer, block } => (
            "compact_fallback",
            serde_json::json!({
                "peer": peer,
                "block": block.to_string(),
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
    fn tail_follows_appends_and_survives_rotation() {
        let dir = tmpdir("tail");
        let path = dir.join(EVENTS_FILENAME);
        let mut tail = EventTail::follow(path.clone());
        assert!(tail.read_new(16).is_empty(), "absent file is idle");
        // A writer starts; a follower at EOF sees only new lines.
        {
            let mut s = EventStream::open(&dir).unwrap();
            s.emit("run_started", serde_json::json!({})).unwrap();
            s.emit("tip_advanced", serde_json::json!({"height": 1}))
                .unwrap();
        }
        let got = tail.read_new(16);
        assert_eq!(got.len(), 2);
        assert_eq!(got[1]["kind"], "tip_advanced");
        // A torn write (no newline) is not consumed mid-line.
        {
            let mut f = File::options().append(true).open(&path).unwrap();
            f.write_all(b"{\"seq\": 99, \"kind\": \"partial\"").unwrap();
        }
        assert!(tail.read_new(16).is_empty(), "torn tail waits");
        {
            let mut f = File::options().append(true).open(&path).unwrap();
            f.write_all(b"}\n").unwrap();
        }
        let got = tail.read_new(16);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["kind"], "partial");
        // Rotation: the old file left, a fresh one starts — the cursor
        // resets instead of dying on a shrunk file.
        std::fs::rename(&path, path.with_extension("ndjson.1")).unwrap();
        {
            let mut s = EventStream::open(&dir).unwrap();
            s.emit("run_started", serde_json::json!({})).unwrap();
        }
        let got = tail.read_new(16);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["kind"], "run_started");
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
                cmpct: None,
                utxproof: false,
            }),
        });
        assert_eq!(kind, "peer_connected");
        assert_eq!(f["peer"], 3);
        assert_eq!(f["user_agent"], "/Satoshi:28.0.0.1/");
        assert_eq!(f["protocol_version"], 70016);
    }
}

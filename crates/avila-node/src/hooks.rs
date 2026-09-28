//! External verdict helpers (docs/DECISION_REGISTRY.md — "External
//! verdict programs"). A helper is a long-lived subprocess consulted at
//! a decision point: one JSON line of facts in, one verdict line back.
//!
//! Helpers can only NARROW acceptance — a `reject` drops the object,
//! `defer` falls to the point's configured default, and nothing a
//! helper says can authorize what built-in checks refused. Failure is
//! supervised: bounded restarts, then the point's `on_timeout` verdict
//! forever (restart budget is never silently exceeded).
//!
//! Wire: `{"point":"peer.accept","seq":7,"facts":{…}}` on stdin →
//! `{"verdict":"accept"|"reject"|"defer","reason":"…"?}` on stdout.
//! Helper stderr passes through to ours so diagnostics reach the
//! operator.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use avila_core::OnDefault;

/// A verdict line's payload — anything past `verdict`/`reason` is
/// ignored so helpers can grow fields without breaking the node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Accept,
    Reject,
    /// The helper declined to decide; the point's `on_defer` default
    /// applies (typically reject for admission points).
    Defer,
}

/// A configured hook — one decision point may run several under
/// conjunction (`Vec<HookSpec>` in `SyncConfig`).
#[derive(Clone, Debug)]
pub struct HookSpec {
    /// Helper executable (relative paths resolve against the config
    /// file's directory).
    pub program: PathBuf,
    pub args: Vec<String>,
    /// Slow = dead: a helper that misses this is killed and counted
    /// against `max_restarts`.
    pub timeout: Duration,
    /// Verdict when the helper can't answer — timeout, crash, or
    /// malformed line. Fail-closed ("reject") for admission points.
    pub on_timeout: OnDefault,
    /// Verdict when the helper says `defer`.
    pub on_defer: OnDefault,
    /// Respawns allowed over the node's lifetime before the point runs
    /// permanently on `on_timeout`.
    pub max_restarts: u32,
}

/// A verdict line larger than this is garbage, not an answer.
const MAX_VERDICT_BYTES: u64 = 64 * 1024;

/// One running helper. `decide` never blocks longer than
/// `spec.timeout` and never panics on a dead child — every failure
/// mode collapses into the spec's declared default.
pub struct VerdictHelper {
    spec: HookSpec,
    child: Child,
    stdin: ChildStdin,
    lines: mpsc::Receiver<String>,
    restarts_used: u32,
    seq: u64,
}

fn spawn_inner(spec: &HookSpec) -> std::io::Result<(Child, ChildStdin, mpsc::Receiver<String>)> {
    let mut child = Command::new(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("helper stdin not piped"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("helper stdout not piped"))?;
    // Reader thread: helper stdout → channel, so `decide` can bound the
    // wait with `recv_timeout`. The thread exits on EOF (dead helper)
    // or when the channel is dropped.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.by_ref().take(MAX_VERDICT_BYTES).read_line(&mut line) {
                // EOF or error — channel closes, caller treats it as a
                // dead helper.
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        return;
                    }
                }
            }
        }
    });
    Ok((child, stdin, rx))
}

fn parse_verdict(line: &str) -> Option<Verdict> {
    let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    match v.get("verdict")?.as_str()? {
        "accept" => Some(Verdict::Accept),
        "reject" => Some(Verdict::Reject),
        "defer" => Some(Verdict::Defer),
        _ => None,
    }
}

impl VerdictHelper {
    /// Spawn the helper. A bad path/permission fails here — callers
    /// decide whether that's startup-fatal or a tombstone (the node
    /// tombstones: a helper that never ran yields `on_timeout` forever,
    /// same as one that exhausted restarts).
    pub fn spawn(spec: HookSpec) -> std::io::Result<Self> {
        let (child, stdin, lines) = spawn_inner(&spec)?;
        Ok(Self {
            spec,
            child,
            stdin,
            lines,
            restarts_used: 0,
            seq: 0,
        })
    }

    /// Consult the helper and resolve the point's defaults —
    /// `decide` answers the only question callers ask: admit or not.
    /// `accept` → true; `reject` → false; `defer`/timeout/crash/garbage
    /// → the spec's `on_defer`/`on_timeout`.
    pub fn decide(&mut self, point: &str, facts: &serde_json::Value) -> bool {
        match self.verdict(point, facts) {
            Verdict::Accept => true,
            Verdict::Reject => false,
            Verdict::Defer => matches!(self.spec.on_defer, OnDefault::Accept),
        }
    }

    /// The raw verdict — `defer` is returned unresolved so callers
    /// logging decisions can report what the helper actually said.
    pub fn verdict(&mut self, point: &str, facts: &serde_json::Value) -> Verdict {
        self.seq += 1;
        let request =
            serde_json::json!({"point": point, "seq": self.seq, "facts": facts}).to_string();
        // Requests are strictly serialized (one outstanding), so a
        // reply can't be misattributed; on timeout the child is killed
        // and replaced rather than left to answer late and poison the
        // next request's read.
        if self
            .stdin
            .write_all(request.as_bytes())
            .and_then(|()| self.stdin.write_all(b"\n"))
            .and_then(|()| self.stdin.flush())
            .is_err()
        {
            return self.fail();
        }
        match self.lines.recv_timeout(self.spec.timeout) {
            Ok(line) => parse_verdict(&line).unwrap_or_else(|| self.fail()),
            // Timeout or a closed channel (dead helper).
            _ => self.fail(),
        }
    }

    /// The helper misbehaved — kill, bounded-restart, and answer with
    /// the point's `on_timeout` default.
    fn fail(&mut self) -> Verdict {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self.restarts_used < self.spec.max_restarts
            && let Ok((child, stdin, lines)) = spawn_inner(&self.spec)
        {
            self.child = child;
            self.stdin = stdin;
            self.lines = lines;
            self.restarts_used += 1;
        }
        match self.spec.on_timeout {
            OnDefault::Accept => Verdict::Accept,
            OnDefault::Reject => Verdict::Reject,
        }
    }
}

impl Drop for VerdictHelper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn helper_script(dir: &Path, name: &str, body: &str) -> HookSpec {
        let path = dir.join(name);
        fs::write(&path, body).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        HookSpec {
            program: path,
            args: Vec::new(),
            timeout: Duration::from_secs(2),
            on_timeout: OnDefault::Reject,
            on_defer: OnDefault::Reject,
            max_restarts: 1,
        }
    }

    fn tmpdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("avila-hook-test-{name}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A freshly-written script can briefly fail exec with ETXTBSY
    /// (error 26) under test parallelism — retry the spawn only.
    fn spawn_retry(spec: HookSpec) -> VerdictHelper {
        for _ in 0..40 {
            match VerdictHelper::spawn(spec.clone()) {
                Ok(h) => return h,
                Err(e) if e.raw_os_error() == Some(26) => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => panic!("spawn {}: {e}", spec.program.display()),
            }
        }
        panic!("helper never became executable");
    }

    const ACCEPT_ALL: &str =
        "#!/bin/sh\nwhile IFS= read -r line; do echo '{\"verdict\":\"accept\"}'; done\n";

    #[test]
    fn accept_verdict_admits() {
        let spec = helper_script(&tmpdir("accept"), "accept.sh", ACCEPT_ALL);
        let mut h = spawn_retry(spec);
        assert!(h.decide(
            "peer.accept",
            &serde_json::json!({"remote": "1.2.3.4:8333"})
        ));
    }

    #[test]
    fn reject_verdict_drops() {
        let spec = helper_script(
            &tmpdir("reject"),
            "reject.sh",
            "#!/bin/sh\nwhile IFS= read -r line; do echo '{\"verdict\":\"reject\",\"reason\":\"testnet\"}'; done\n",
        );
        let mut h = spawn_retry(spec);
        assert!(!h.decide("peer.accept", &serde_json::json!({})));
    }

    #[test]
    fn defer_uses_on_defer_default() {
        let mut spec = helper_script(
            &tmpdir("defer"),
            "defer.sh",
            "#!/bin/sh\nwhile IFS= read -r line; do echo '{\"verdict\":\"defer\"}'; done\n",
        );
        spec.on_defer = OnDefault::Accept;
        let mut h = spawn_retry(spec);
        assert!(h.decide("peer.accept", &serde_json::json!({})));
    }

    #[test]
    fn helper_receives_the_facts() {
        // Reject only when facts mark port 6666 — proves the request
        // line carries real fields, not a stub.
        let spec = helper_script(
            &tmpdir("facts"),
            "facts.sh",
            "#!/bin/sh\nwhile IFS= read -r line; do case \"$line\" in *6666*) echo '{\"verdict\":\"reject\"}' ;; *) echo '{\"verdict\":\"accept\"}' ;; esac; done\n",
        );
        let mut h = spawn_retry(spec);
        assert!(h.decide(
            "peer.accept",
            &serde_json::json!({"remote": "1.2.3.4:8333"})
        ));
        assert!(!h.decide(
            "peer.accept",
            &serde_json::json!({"remote": "1.2.3.4:6666"})
        ));
    }

    #[test]
    fn timeout_yields_on_timeout_and_restarts() {
        // Never answers → every ask hits the timeout → on_timeout, and
        // the restart budget burns once per ask then stops.
        let mut spec = helper_script(&tmpdir("timeout"), "timeout.sh", "#!/bin/sh\nsleep 3600\n");
        spec.timeout = Duration::from_millis(50);
        spec.max_restarts = 1;
        let mut h = spawn_retry(spec);
        assert!(!h.decide("peer.accept", &serde_json::json!({})));
        assert!(!h.decide("peer.accept", &serde_json::json!({})));
        assert!(!h.decide("peer.accept", &serde_json::json!({})));
    }

    #[test]
    fn crash_recovers_once_within_restart_budget() {
        // Dies on first line, then accepts on respawn — one restart.
        let spec = helper_script(
            &tmpdir("crash"),
            "crash.sh",
            "#!/bin/sh\nread line || exit 1\nexit 0\n",
        );
        let mut h = spawn_retry(spec);
        // First ask: child exits without answering → on_timeout.
        assert!(!h.decide("peer.accept", &serde_json::json!({})));
        // Restart budget spent (1): the replacement also dies fast.
        assert!(!h.decide("peer.accept", &serde_json::json!({})));
        // Budget exhausted → permanent on_timeout, no more spawns.
        assert!(!h.decide("peer.accept", &serde_json::json!({})));
    }

    #[test]
    fn malformed_lines_are_a_failure_not_a_verdict() {
        let spec = helper_script(
            &tmpdir("garbage"),
            "garbage.sh",
            "#!/bin/sh\nwhile IFS= read -r line; do echo 'not json'; done\n",
        );
        let mut h = spawn_retry(spec);
        assert!(!h.decide("peer.accept", &serde_json::json!({})));
    }

    /// The `tx.admit` seam end-to-end: a real helper subprocess gates
    /// `Mempool::accept_tx`. No funded chain needed — the hook consults
    /// before the built-in checks, so a reject lands as `PolicyHook`
    /// and an accept falls through to the normal verdict.
    #[test]
    fn tx_admit_helper_gates_the_mempool() {
        use avila_consensus::chainstate::Chainstate;
        use avila_consensus::params::Network;
        use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut};
        use avila_mempool::{Mempool, MempoolReject};

        let cs = Chainstate::new(&Network::Regtest.params());
        let junk_tx = || Transaction {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: avila_consensus::hash::Txid::from_bytes([7u8; 32]),
                    vout: 0,
                },
                script_sig: Script::new(vec![]),
                sequence: 0xffff_ffff,
                witness: Default::default(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: Script::new(vec![0x51]),
            }],
            lock_time: 0,
        };

        // Rejecting helper → PolicyHook before any built-in check runs.
        let spec = helper_script(&tmpdir("txadmit-reject"), "reject.sh", {
            "#!/bin/sh\nwhile IFS= read -r line; do echo '{\"verdict\":\"reject\",\"reason\":\"not this tx\"}'; done\n"
        });
        let mut helper = spawn_retry(spec);
        let mut pool = Mempool::new();
        pool.set_require_standard(false);
        pool.set_admit_hook(Some(Box::new(move |f: &avila_mempool::TxAdmitFacts| {
            let facts = serde_json::json!({
                "txid": f.txid.to_string(),
                "fee": f.fee,
                "rbf": f.rbf,
                "spk_types": f.spk_types,
            });
            matches!(helper.verdict("tx.admit", &facts), Verdict::Accept)
        })));
        assert!(matches!(
            pool.accept_tx(junk_tx(), &cs, 1_700_000_000),
            Err(MempoolReject::PolicyHook)
        ));

        // Accepting helper → the tx falls through to the real checks
        // (unresolvable prevout → the usual orphan verdict).
        let spec = helper_script(&tmpdir("txadmit-accept"), "accept.sh", ACCEPT_ALL);
        let mut helper = spawn_retry(spec);
        pool.set_admit_hook(Some(Box::new(move |f: &avila_mempool::TxAdmitFacts| {
            let facts = serde_json::json!({"txid": f.txid.to_string()});
            matches!(helper.verdict("tx.admit", &facts), Verdict::Accept)
        })));
        assert!(matches!(
            pool.accept_tx(junk_tx(), &cs, 1_700_000_000),
            Err(MempoolReject::InputsMissingOrSpent)
        ));
    }
}

//! Signer process boundary (queue #39): key material lives in a
//! spawned `avila signer` subprocess, never in the node process. The
//! node pipes PSBTs over the child's stdin/stdout (JSON-lines); the
//! child signs and replies. A compromised network-facing process can
//! ask for signatures but cannot read keys — defense-in-depth, not an
//! airgap (same kernel; an attacker who can ptrace/exec already owns
//! the box).
//!
//! Protocol (one JSON object per line):
//! - parent → child `{"vault": path, "passphrase": str}` at spawn;
//!   child replies `{"ok": true}` or `{"error": msg}`.
//! - `{"sign_psbt": b64}` → `{"psbt": b64, "complete": bool}`.
//! - `{"lock": true}` → child exits 0.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

/// A live `avila signer` child — the wallet's out-of-process signer.
pub struct SignerProc {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl std::fmt::Debug for SignerProc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignerProc")
            .field("pid", &self.child.id())
            .finish()
    }
}

impl SignerProc {
    /// Spawn `exe signer` and unlock `vault` inside it. The passphrase
    /// crosses the pipe once at handshake — it never sits in the
    /// child's argv (visible in /proc).
    pub fn spawn(
        exe: &Path,
        vault: &Path,
        passphrase: &str,
        network: avila_consensus::params::Network,
    ) -> Result<Self, String> {
        let mut child = Command::new(exe)
            .arg("signer")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("signer spawn failed: {e}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "signer stdin missing".to_string())?;
        let stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| "signer stdout missing".to_string())?,
        );
        let mut proc = Self {
            child,
            stdin,
            stdout,
        };
        let hello = serde_json::json!({
            "vault": vault.display().to_string(),
            "passphrase": passphrase,
            "network": network.name(),
        });
        let reply = proc
            .request(&hello)
            .map_err(|e| format!("signer handshake failed: {e}"))?;
        if reply.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            let msg = reply
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let _ = proc.child.kill();
            return Err(format!("signer refused vault: {msg}"));
        }
        Ok(proc)
    }

    /// One request line, one reply line.
    pub fn request(&mut self, req: &serde_json::Value) -> Result<serde_json::Value, String> {
        let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| format!("signer write: {e}"))?;
        let mut buf = String::new();
        self.stdout
            .read_line(&mut buf)
            .map_err(|e| format!("signer read: {e}"))?;
        if buf.is_empty() {
            return Err("signer closed the pipe".into());
        }
        serde_json::from_str(buf.trim()).map_err(|e| format!("signer reply malformed: {e}"))
    }

    /// Sign the PSBT in the child — prevouts were already verified and
    /// filled by the node against its own UTXO set.
    pub fn sign_psbt(&mut self, psbt_b64: &str) -> Result<(String, bool), String> {
        let reply = self.request(&serde_json::json!({ "sign_psbt": psbt_b64 }))?;
        if let Some(e) = reply.get("error").and_then(|v| v.as_str()) {
            return Err(e.to_string());
        }
        let psbt = reply
            .get("psbt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "signer reply missing psbt".to_string())?;
        let complete = reply
            .get("complete")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        Ok((psbt.to_string(), complete))
    }

    /// Ask the child to drop keys and exit.
    pub fn lock(&mut self) {
        let _ = self.request(&serde_json::json!({ "lock": true }));
        let _ = self.child.wait();
    }
}

impl Drop for SignerProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

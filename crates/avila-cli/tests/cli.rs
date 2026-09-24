#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_avila-node"))
}

/// A fresh scratch directory under the OS temp dir, unique per test —
/// `tag` plus pid plus a nanosecond timestamp, since several of these
/// tests run in parallel threads of the same process.
fn scratch_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "avila-cli-test-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes a minimal config under `root` whose network data directory
/// resolves to `root/data/regtest` (data_dir is relative to the
/// config file itself, not the process's cwd).
fn write_config(root: &Path) -> PathBuf {
    let path = root.join("config.toml");
    std::fs::write(
        &path,
        "schema_version = 1\nnetwork = \"regtest\"\ndata_dir = \"data\"\nevent_capacity = 256\n",
    )
    .unwrap();
    path
}

/// A minimal `backup`-shaped directory `migrate --rollback`/`restore`
/// will accept: the manifest marker they check for, plus a `state.dat`
/// that also passes `migrate`'s own post-rollback compatibility report
/// (regtest magic + the binary's STATE_VERSION) so a successful
/// rollback's exit code reflects the rollback alone.
fn fake_backup(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("backup-manifest.json"), "{}").unwrap();
    let mut state = avila_consensus::params::Network::Regtest
        .params()
        .message_start
        .to_vec();
    state.extend_from_slice(&avila_consensus::store::STATE_VERSION.to_le_bytes());
    std::fs::write(dir.join("state.dat"), &state).unwrap();
}

#[test]
fn configuration_check_succeeds() {
    let output = cli().arg("check-config").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Configuration valid"));
}

#[test]
fn inspection_is_explicit_and_has_no_fake_tip() {
    let output = cli().args(["inspect", "--json"]).output().unwrap();
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["scope"], "local_inspection");
    assert!(value["validated_tip_height"].is_null());
    assert!(value["connected_peers"].is_null());
    assert_eq!(value["historical_validation_complete"], false);
}

#[test]
fn run_with_no_peers_fails_honestly() {
    // `run` is a real daemon: on regtest with no seeds it keeps
    // redialing rather than exiting (Core never exits on zero peers),
    // so the fail-fast check lives on `sync` — the bounded one-shot —
    // which still reports honestly instead of pretending to sync.
    let output = cli().arg("sync").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no peer candidates"));
}

#[test]
fn unknown_arguments_are_errors() {
    assert!(!cli().arg("--imaginary").status().unwrap().success());
}

#[test]
fn missing_config_is_an_error_not_a_silent_default() {
    let output = cli()
        .args([
            "--config",
            "missing-configuration-fixture.toml",
            "check-config",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn migrate_rollback_refuses_a_nonempty_datadir_without_force() {
    let root = scratch_dir("migrate-rollback-nonempty");
    let config = write_config(&root);
    let live = root.join("data").join("regtest");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::write(live.join("state.dat"), b"live-state").unwrap();
    let backup = root.join("backup");
    fake_backup(&backup);

    let output = cli()
        .args([
            "--config",
            config.to_str().unwrap(),
            "migrate",
            "--rollback",
            backup.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("non-empty"), "{stderr}");
    assert!(stderr.contains("--force"), "{stderr}");
    // Refused, so the live file must survive untouched.
    assert_eq!(
        std::fs::read(live.join("state.dat")).unwrap(),
        b"live-state"
    );

    // --force clears the same refusal and performs the rollback.
    let output = cli()
        .args([
            "--config",
            config.to_str().unwrap(),
            "migrate",
            "--rollback",
            backup.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read(live.join("state.dat")).unwrap(),
        std::fs::read(backup.join("state.dat")).unwrap(),
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn migrate_rollback_refuses_a_locked_datadir_even_with_force() {
    let root = scratch_dir("migrate-rollback-locked");
    let config = write_config(&root);
    let live = root.join("data").join("regtest");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::write(live.join("state.dat"), b"live-state").unwrap();
    let backup = root.join("backup");
    fake_backup(&backup);

    // Hold the datadir lock ourselves, the way a running node would.
    let lock_file = std::fs::File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(live.join(".lock"))
        .unwrap();
    lock_file.try_lock().unwrap();

    let output = cli()
        .args([
            "--config",
            config.to_str().unwrap(),
            "migrate",
            "--rollback",
            backup.to_str().unwrap(),
            "--force",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("locked"), "{stderr}");
    // The lock check must run before --force ever gets a say, so the
    // live file survives.
    assert_eq!(
        std::fs::read(live.join("state.dat")).unwrap(),
        b"live-state"
    );

    drop(lock_file);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn migrate_reports_truncated_index_files_instead_of_panicking() {
    let root = scratch_dir("migrate-truncated-index");
    let config = write_config(&root);
    let live = root.join("data").join("regtest");
    std::fs::create_dir_all(&live).unwrap();
    // The correct 4-byte "cflt" magic, but only one byte of the u32
    // version that should follow it — this used to panic slicing
    // raw[4..8] on the short file instead of reporting it.
    std::fs::write(live.join("cfilters.dat"), b"cflt\x01").unwrap();

    let output = cli()
        .args(["--config", config.to_str().unwrap(), "migrate"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "migrate_report panicked instead of reporting it: {stderr}"
    );
    assert_ne!(
        output.status.code(),
        Some(101),
        "101 is Rust's uncaught-panic exit code: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("cfilters.dat: INCOMPATIBLE — truncated"),
        "{stdout}"
    );
    // Still reported as incompatible, so the command fails — just not
    // by crashing.
    assert!(!output.status.success());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
#[cfg(unix)]
fn backup_skips_symlinks_instead_of_dereferencing_them() {
    let root = scratch_dir("backup-symlink");
    let config = write_config(&root);
    let live = root.join("data").join("regtest");
    std::fs::create_dir_all(&live).unwrap();
    std::fs::write(live.join("real.dat"), b"real-content").unwrap();
    // Outside the datadir entirely — copy_tree following this would
    // pull unrelated data into the backup under an innocuous name.
    let secret = root.join("outside-secret.txt");
    std::fs::write(&secret, b"outside-secret").unwrap();
    std::os::unix::fs::symlink(&secret, live.join("link.dat")).unwrap();

    let dest = root.join("backup_out");
    let output = cli()
        .args(["--config", config.to_str().unwrap(), "backup"])
        .arg(&dest)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("skipping symlink"), "{stderr}");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let target = stdout
        .lines()
        .find_map(|l| {
            l.strip_prefix("Backed up ")
                .and_then(|r| r.split_once(" file(s) to "))
        })
        .map(|(_, path)| PathBuf::from(path))
        .expect("backup summary line");

    assert_eq!(
        std::fs::read(target.join("real.dat")).unwrap(),
        b"real-content"
    );
    assert!(
        !target.join("link.dat").exists(),
        "the symlink must not be materialized in the backup"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(target.join("backup-manifest.json")).unwrap())
            .unwrap();
    let files: Vec<&str> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(files.contains(&"real.dat"));
    assert!(!files.contains(&"link.dat"));

    let _ = std::fs::remove_dir_all(&root);
}

/// Queue #39's live boundary: the `avila-node signer` subprocess
/// unlocks a vault and signs a PSBT whose prevout script belongs to
/// the vault's derived keys — all over the stdio pipe.
#[test]
fn signer_subprocess_signs_and_locks() {
    use avila_consensus::extended_key::ExtKey;
    use avila_consensus::params::Network;
    use avila_consensus::psbt::Psbt;
    use avila_consensus::transaction::{OutPoint, Script, Transaction, TxIn, TxOut, Witness};

    let params = Network::Regtest.params();
    // A deterministic seed → BIP84 account → private wpkh descriptor.
    let seed = [9u8; 32];
    let master = ExtKey::from_seed(&seed, params.base58_ext_secret_prefix).unwrap();
    const H: u32 = 0x8000_0000;
    let acct = master
        .derive(84 | H)
        .and_then(|k| k.derive(1 | H))
        .and_then(|k| k.derive(H))
        .unwrap();
    let fp: String = master
        .fingerprint()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let body = format!("wpkh([{fp}/84h/1h/0h]{}/0/*)", acct.encode());
    let desc = format!(
        "{body}#{}",
        avila_consensus::descriptor::descriptor_checksum(&body)
    );

    // The prevout script for index 0 — expand the desc with the
    // private provider (the child's provider is rebuilt the same way).
    let provider =
        avila_node::watch::signer_provider_from_descs(std::slice::from_ref(&desc), &params)
            .unwrap();
    let (parsed, _, _) =
        avila_consensus::descriptor::parse_descriptors(&desc, &params, true).unwrap();
    let scripts = parsed[0].expand(0, &provider).unwrap();
    let spk = scripts
        .iter()
        .find(|s| s.len() == 22 && s[0] == 0x00 && s[1] == 0x14)
        .unwrap()
        .clone();

    // Seal a vault carrying the private desc.
    let root = scratch_dir("signer-boundary");
    let vault = root.join("signervault.dat");
    let state = avila_node::watch::SignerState {
        provider: provider.clone(),
        descs_private: vec![desc],
        descs_watch: Vec::new(),
        provenance: "test".into(),
        entropy_commitment: String::new(),
    };
    std::fs::write(&vault, avila_node::watch::vault_seal(&state, "pw").unwrap()).unwrap();

    // Spawn the real subprocess and have it sign.
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_avila-node"));
    let mut proc =
        avila_node::signerproc::SignerProc::spawn(&exe, &vault, "pw", Network::Regtest).unwrap();
    let tx = Transaction {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: avila_consensus::hash::Txid::from_bytes([0x22; 32]),
                vout: 0,
            },
            script_sig: Script::new(Vec::new()),
            sequence: 0xffff_ffff,
            witness: Witness::default(),
        }],
        outputs: vec![TxOut {
            value: 25_000,
            script_pubkey: Script::new(vec![0x51]),
        }],
        lock_time: 0,
    };
    let mut psbt = Psbt::from_unsigned_tx(tx);
    let mut v = 50_000i64.to_le_bytes().to_vec();
    avila_consensus::encode::write_var_bytes(&mut v, &spk);
    psbt.inputs[0].set(vec![Psbt::IN_WITNESS_UTXO], v);
    let b64 = base64(&psbt.encode());
    let (signed_b64, complete) = proc.sign_psbt(&b64).unwrap();
    assert!(complete, "child must sign the spend of its own key");
    let signed = Psbt::decode(&unbase64(&signed_b64)).unwrap();
    assert!(signed.inputs[0].get(Psbt::IN_FINAL_SCRIPTWITNESS).is_some());
    proc.lock();
    let _ = std::fs::remove_dir_all(&root);
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = c.iter().fold(0u32, |a, &x| (a << 8) | x as u32) << (8 * (3 - c.len()));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn unbase64(s: &str) -> Vec<u8> {
    fn v(b: u8) -> u32 {
        match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    }
    let s = s.trim_end_matches('=');
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in s.as_bytes() {
        acc = (acc << 6) | v(b);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

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

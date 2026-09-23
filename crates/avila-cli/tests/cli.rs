#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_avila-node"))
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

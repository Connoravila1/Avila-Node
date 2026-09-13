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
fn run_fails_instead_of_pretending_to_be_a_node() {
    let output = cli().arg("run").output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not implemented"));
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

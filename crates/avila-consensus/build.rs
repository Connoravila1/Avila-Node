// Embeds the build's source identity so run manifests can attribute a
// binary to the revision it was compiled from — a runtime `git
// rev-parse` would report whatever the checkout happens to point at.
fn main() {
    let rev = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let dirty = std::process::Command::new("git")
        .args(["-C", env!("CARGO_MANIFEST_DIR"), "status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false);
    println!(
        "cargo:rustc-env=AVILA_GIT_REV={rev}{}",
        if dirty { "+dirty" } else { "" }
    );
    println!("cargo:rerun-if-env-changed=AVILA_GIT_REV");
}

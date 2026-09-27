// Embeds the build's source identity so run manifests can attribute a
// binary to the revision it was compiled from — a runtime `git
// rev-parse` would report whatever the checkout happens to point at.
// `rerun-if-changed` on .git/HEAD + the ref it names forces a rebuild
// when the commit moves, so an incremental rebuild cannot keep a stale
// identity.
fn main() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let head_path = format!("{root}/.git/HEAD");
    println!("cargo:rerun-if-changed={head_path}");
    if let Ok(head) = std::fs::read_to_string(&head_path) {
        // HEAD → "ref: refs/heads/<branch>" — also watch the branch tip
        // file, or a commit that doesn't move HEAD goes unnoticed.
        if let Some(r) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed={root}/.git/{r}");
        }
    }
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
}

# Development

Read the [scope](docs/SCOPE.md), [architecture](docs/ARCHITECTURE.md) and
[roadmap](ROADMAP.md) before changing behavior. This is an MIT-licensed project
intended for public use, hosted under Connor Avila's personal GitHub account.
Work in this repository is consolidated on `main`; do not
create extra branches as an automatic scaffolding step.

Use the pinned toolchain and committed `Cargo.lock`. Keep dependency updates
deliberate and inspect their feature graph. The normal checks are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo run --locked -p avila-cli -- --config config/default.toml check-config
cargo run --locked -p avila-cli -- inspect --json
```

For headless-only work, `cargo test --locked -p avila-core -p avila-node -p avila-cli`
does not compile the GUI. Changes to shared contracts still require a workspace
check before integration.

Use typed failures, bounded inputs and explicit state. Add tests that exercise
meaningful invariants and failure cases. Future consensus changes need valid and
invalid fixtures, activation/chain context, and differential evidence; successful
decoding or matching one historical block is insufficient.

`avila-consensus` has two optional test layers beyond `cargo test`: deterministic
property tests in `crates/avila-consensus/tests/property.rs` (run with the rest of
the suite), and a libFuzzer harness in `fuzz/` — a standalone nightly workspace
that does not affect the root lockfile:

```sh
cd fuzz
cargo +nightly fuzz build            # requires a nightly toolchain + cargo-fuzz
cargo +nightly fuzz run decode-block # one of the six targets
```

Corpora, crash artifacts and `fuzz/target/` are gitignored. Minimize any crash to
a regression test in the crate before fixing.

Run `cargo run --locked -p avila-gui` in a graphical session after interface changes.
Check keyboard navigation, small windows, increased zoom, long text, empty data,
and errors. Rendering tests complement native interaction checks.

Document concrete before/after behavior, validation, and remaining limitations.
Update capabilities only when their implementation and acceptance tests exist.
Use the [experiment template](experiments/TEMPLATE.md) and
[scorecard](docs/SCORECARD.md) for performance or behavior comparisons. Identify
the matched operating profile and complete verification workload; publish regressions
and external helper costs alongside wins. Do not commit personal configuration,
chain data, wallet material, raw traffic captures or unrestricted diagnostic logs.

<img src="assets/avila-node-logo.png" alt="Avila Node orange AN logo" width="120" height="120">

# Avila Node

An open-source, MIT-licensed Bitcoin full node by **Connor Avila**, written in Rust
with a native **egui** desktop interface. Hosted under Connor's personal GitHub
account, Avila Node is intended for public use once its release requirements are met.

The ambition is to build the best complete node across correctness, validation
speed, resource efficiency, privacy, resilience, wallet and mining services, and
usability. Feature parity is an intermediate step. We will pursue improvements
against the strongest reproducible alternatives in each operating profile, and
publish the tradeoffs and remaining gaps in a [measurement scorecard](docs/SCORECARD.md).
This is a goal to earn through evidence, not a claim about today's implementation.

The deliverable is an independently usable primary node. Reusable components and
reproducible findings are additional contributions to other projects. Experimental
describes the current development maturity and research, not a limit on the ambition
or an intention to keep the software for its author alone.

## Current state

This is the application foundation. Configuration validation, local inspection,
bounded diagnostic events, a headless CLI, and a native desktop shell are implemented.
**Bitcoin consensus validation, chain storage, peer networking, synchronization,
mempool, relay, and wallet services are still to be built.**

`run` currently exits with an explicit error. Inspection and the desktop show the
local process and configuration, with unavailable chain and peer measurements.
Selecting a network does not connect to it. See the [roadmap](ROADMAP.md) for the
implementation sequence and acceptance criteria.

## Run the foundation

Install [Rust through rustup](https://www.rust-lang.org/tools/install). The repository
pins Rust 1.98.1 and eframe/egui 0.36.2; `Cargo.lock` fixes the dependency resolution.

On Debian/Ubuntu, native desktop development requires:

```sh
sudo apt-get install build-essential pkg-config libxkbcommon-dev libwayland-dev libx11-dev libxi-dev libgl1-mesa-dev libudev-dev
```

```sh
cargo run --locked -p avila-cli -- --config config/default.toml check-config
cargo run --locked -p avila-cli -- inspect --json
cargo run --locked -p avila-gui -- --config config/default.toml
```

The CLI builds independently of the GUI and does not require a display. The desktop
requires a native graphical session. Its menus, resizable navigation, searchable
tables, event details, appearance controls, and keyboard shortcuts operate on the
available local state. Further egui capabilities are mapped to their intended uses
in the [GUI plan](docs/GUI.md).

Choose **View → Appearance** for **Light**, **Dark**, or **Black** (fully black panel
and window backgrounds), plus interface scaling. Theme and scale are remembered
on this device. To choose a theme at startup:

```sh
cargo run --locked -p avila-gui -- --theme black
```

`--theme light|dark|black` overrides the saved theme and becomes the new preference
when the application saves. Appearance is stored separately from node configuration.

Copy `config/default.toml` to the ignored `config/local.toml` for personal settings.
Relative data paths resolve against the configuration file's directory; without a
file, the default `data/` is relative to the working directory. Each network gets a
separate subdirectory. Inspection does not create that directory.

## Project map

| Path | Responsibility |
| --- | --- |
| `crates/avila-core` | Pure configuration validation and shared status contracts |
| `crates/avila-node` | Configuration I/O, coordination, bounded local event history |
| `crates/avila-cli` | Headless `avila-node` executable |
| `crates/avila-gui` | Native egui application; presentation stays outside validation |
| `config` | Documented development configuration |
| `docs` | [Scope](docs/SCOPE.md), [architecture](docs/ARCHITECTURE.md), [GUI plan](docs/GUI.md) |
| `experiments` | Reproducible experiment guidance and result template |
| `assets` | Project branding supplied by Connor Avila |

Future consensus, storage, P2P, mempool, and service components will receive their
own boundaries as they are implemented. Empty crates are not counted as features.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

See [contribution guidance](CONTRIBUTING.md) and the [experiment template](experiments/TEMPLATE.md).
Repository work is consolidated on `main`.
The [foundation review](docs/FOUNDATION_REVIEW.md) records the scaffold audit and validation limits.

## License

[MIT](LICENSE), copyright 2026 Connor Avila. The supplied logo is included with the project.

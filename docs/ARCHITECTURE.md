# Architecture

## Current boundaries

```mermaid
flowchart TD
    CLI[Headless CLI] --> NODE[Node coordinator and I/O]
    GUI[egui desktop] --> NODE
    NODE --> CORE[Pure configuration and status contracts]
    GUI --> CORE
    NODE --> EVENTS[Bounded process-local diagnostic history]
```

`avila-core` has no filesystem, network, clock, or GUI operations. Configuration is
deserialized into an unvalidated type; only validation produces the private-field
`ValidatedConfig`. `avila-node` owns file loading, lifecycle, and events. Both
executables inspect that coordinator. Today it does not spawn workers or run a daemon.

The startup gate remains closed until validation, storage, and networking actually
exist. `NodeSnapshot` deliberately uses optional measurements and identifies its
scope as `local_inspection`. The event journal is bounded process-local diagnostics,
not a consensus transaction log or a backup mechanism.

## Intended component boundaries

| Component | Owns | Must not depend on |
| --- | --- | --- |
| Consensus | Deterministic parsing, validation, state-transition rules | GUI, policy preferences, filesystem or sockets |
| Chain/storage | Blocks, UTXOs, atomic commits, undo, recovery | Desktop state |
| P2P/sync | Peer lifecycle, bounded I/O, scheduling and acquisition | GUI rendering |
| Mempool/policy | Admission, packages, relay policy and explanations | Authority to alter block-validity rules |
| Coordinator | Lifecycle, limits, cancellation, command handling | A graphical session |
| Services/indexes | Explicitly scoped queries, wallet scans and indexing | Implicit access to signing keys or administration |
| CLI/GUI | Commands, snapshots, explanations, interaction | Direct writes to consensus state |

Create these modules/crates when implementing their first complete behavior. Keep
interfaces small enough to extract useful implementations into other node projects.
The architecture specifies responsibilities, not empty success-returning services.

## Kernel and profiles

The organizing direction is a kernel-and-profiles split, enforced by interface
discipline rather than convention.

**The kernel** is the consensus engine plus the state transitions it guarantees:
parsing, script, UTXO semantics, chain selection, undo. Consensus rules are fixed
by the network, never by configuration — the kernel's API must not expose them as
options. Every deployment shares the same kernel; that is what keeps the project
experimental without ever becoming a fork vehicle.

**Profiles** are named bundles of everything else: storage engine and footprint,
sync strategy, mempool and relay policy, indexes, privacy routes, and interfaces.
One binary selects a profile; a profile cannot select consensus behavior. Storage
(`CoinsBackend`), block sources, policy engines, and signers are the pluggable
slots — sized so implementations can be swapped and measured against each other.

**Interface discipline** is the mechanism. Components reach each other only
through defined seams — no reaching inside another component's consensus-relevant
state. Seams are also where verification coverage is reported: validation results
carry *what was checked and what was assumed* as typed outputs, so a profile
cannot claim checks it did not perform. Snapshot-assisted state is labeled as such
by construction, not by documentation.

**Extensions live out of process.** Indexers and application-facing consumers use
wire interfaces; serving token or application data is not a roadmap item. The
interfaces remain neutral — what others build on them is their code, not the
node's direction.

This reframes the workstreams: consensus assurance (W1) hardens the kernel;
storage (W4), sync (W3), policy (W7), privacy (W9), and interfaces (W11) are
profile dimensions; differential testing and the scorecard measure whether the
seams hold their claims.

## Data and concurrency

Validation receives explicit chain context and produces typed results. Distinguish
decoding, context-independent checks, contextual acceptance, and local policy.
Cache keys must capture the identity and context of the check, including witness
data and activation/chain state where relevant. Reorgs change contextual conclusions.

Future workers publish immutable snapshots and bounded events to the coordinator.
Commands have identifiers and explicit completion/failure results. The GUI must
not perform validation, blocking I/O, or unbounded event draining during painting.
Coalesce metrics, cap history, make cancellation cooperative, and request repaint
when new data arrives. GUI failure must not become consensus failure.

The remote/daemon control protocol and process-isolation model remain design
decisions. A Rust module boundary alone is not a privilege or process boundary.

## Correctness and trust

Consensus compatibility is a dedicated engineering task. The
[rust-bitcoin project explicitly cautions against treating its library as a full consensus engine](https://github.com/rust-bitcoin/rust-bitcoin#consensus).
Using its types or vetted cryptography would not by itself establish full validation.
Evaluate the validation implementation and reference adapter against pinned
[Bitcoin Core functional tests](https://github.com/bitcoin/bitcoin/tree/master/test/functional)
and independently sourced valid/invalid fixtures.

### Validation-engine decision (recorded for G1)

**Decision: first-party validation.** `avila-consensus` is the validation
engine — implemented from Bitcoin Core's consensus code as the specification,
not by binding to an existing engine. The alternatives were rejected for
distinct reasons:

- `rust-bitcoin` in the validation path: its own documentation cautions
  against consensus use; its `Target::from_compact` already diverges from
  Core on sign-bit-set compact encodings with `size <= 3` (see
  docs/RULE_INVENTORY.md). It remains a dev-dependency — a differential
  *reference*, never validation code.
- `bitcoinkernel` / a Core shared library: cedes the validation boundary to
  C++ internals, contradicts the unsafe-free workspace policy, and makes
  per-rule evidence collection harder. The installed `bitcoind` instead
  serves as the *external* reference through `tools/check_headers_core.py`
  — a process boundary, not a link boundary.

**Trusted dependencies.** The consensus crate's production dependency surface
is `sha2` (hashing) and `thiserror` (error derives). `bitcoin`, `proptest`
and `libfuzzer-sys` are dev/fuzz-only; the `bitcoind` reference daemon and
Python tooling are developer-time verification and never link into the node.

**Extraction boundary.** `avila-consensus` performs no filesystem, network,
clock or GUI operations — every contextual input (time, ancestry, params) is
explicit. Tests, the `check_headers` example and the `fuzz/` workspace sit
outside the library surface, so the engine can be lifted into other node
projects intact; the verification harness would need its fixtures and tools,
which are committed alongside it.

Track the active chain, fully validated history, snapshot assumptions, index coverage
and connection freshness independently. Optional indexes live beside the chainstate —
`txindex.dat`, `cfilters.dat` (BIP158) and `scindex.dat` (scripthash, for the
Electrum server) — each a resumable append log that rewinds with reorgs and
backfills from retained bodies on first enable. With `-peerblockfilters`
the filter index also answers BIP157 `getcfilters`/`getcfheaders`/
`getcfcheckpt` peer requests; the peer layer then advertises
`NODE_COMPACT_FILTERS` and disconnects requesters of unadvertised types,
matching Core's `PrepareBlockFilterRequest` rules. The distinction between active and background
chainstates is illustrated by [Core's AssumeUTXO design](https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md).
`loadtxoutset`/`dumptxoutset` operate on the single chainstate with Core's
snapshot format. Background validation replays stored pre-base bodies into an
independent UTXO set on the sync tick and proves the loaded set by recomputing
the chainparams content hash — the security property of Core's two-chainstate
model without duplicating the block index; a restart replays from height 1
rather than resuming mid-replay, and `getchainstates` reports the replay as a
second `validated: true` entry until it completes.

Future network inputs, service permissions, queues, disk use, log payloads and
configuration sizes require explicit limits. Preserve provenance and redaction
boundaries in any diagnostic export. Never treat a majority of implementations
as an automatic rule for resolving a consensus disagreement.

### Untrusted-advice invariants (acceleration must never become dependency)

Several fast paths accept *untrusted* auxiliary data — a prepared snapshot
index, SHA-256 midstate hints, signature-verification hints. These are
permitted under a strict rule: advice may accelerate verification; it may
never *become* the verification. Every hint channel must satisfy:

- **False acceptance impossible.** A wrong hint can only cause false
  rejection or wasted work, never acceptance of wrong data. The correctness
  anchor stays a consensus-pinned value (e.g. `hash_serialized`) or the
  object's own validity — never a publisher's identity or signature.
- **The slow path is first-class, permanently.** A node ignoring all advice
  must reach identical correctness by pure local verification, and that path
  stays exercised in tests. A hint path that becomes the only tested path
  is a hidden dependency.
- **Anyone can produce the artifacts.** Hints are derivable from public data
  by any holder of it — no secret inputs, no publisher-only capability. The
  generator ships in the repository with an open format specification.
- **Reproducible outputs.** Two producers building from the same input emit
  the identical root/digest, so operators can cross-check producers and a
  lying publisher is publicly detectable.
- **No availability dependence.** Missing, corrupt, or throttled advice
  degrades to ordinary verification — never stalls, crashes, or alters what
  the node accepts. Worst case is the unassisted path's speed.
- **Provenance ≠ correctness.** Publisher signatures may mark origin but
  carry no correctness weight; verification anchors to consensus values.

The failure mode these rules prevent is soft centralization: bundles that
become de-facto required because the slow path bit-rots or only one party
can produce them. A hint that changes *what* the node accepts — rather than
*how fast* it checks — is out of bounds by definition.

## Dependency and state policy

Pin the toolchain and commit the application lockfile. Keep native GUI features
explicit. The current desktop has no HTTP image loader, remote inspection server,
or telemetry. It embeds the supplied logo in the executable.

The desktop persists only a versioned appearance record (Light/Dark/Black and scale)
using eframe's local application storage. Invalid records fall back to defaults;
scale is finite and bounded. `--theme` overrides the saved choice. Generic egui
memory and native window persistence are disabled, so searches, paths, events and
node state are not included in this record. Future layout persistence needs its
own schema and privacy review. Node configuration remains a separate TOML file.

Review new dependencies for actual purpose, license compatibility, supported Rust
version, feature activation, and effect on the trusted code. Workspace source
forbids unsafe Rust; dependency internals have their own review boundaries.

# Roadmap

The destination is a complete node usable independently as a primary Bitcoin node.
Milestones describe observable acceptance gates, not calendar promises. Work on
historical mainnet behavior starts early; regtest alone cannot establish compatibility.
GUI and headless interfaces advance with the same underlying implementation.

## 0. Application foundation

- [x] Personal project identity, MIT license, documented scope and architecture.
- [x] Rust workspace, shared contracts, CLI and native egui shell.
- [x] Strict configuration parsing and separate network data paths.
- [x] Bounded event retention and explicit local capability inspection.
- [x] Committed dependency lockfile and CI for formatting, linting, tests and docs.
- [x] Supplied logo and a GUI plan tied to real operator tasks.
- [ ] Validate native packaging and interaction on each supported desktop platform.

Exit evidence: the workspace checks pass, CLI inspection reports no invented
chain state, and absent node subsystems cause an explicit startup failure.

## 1. Consensus foundations and reference harness

Define bounded wire/consensus decoding, transaction and block identities, numeric
limits, network parameters, proof of work, header linkage, and chainwork. Document
the Rust validation strategy and any reference-engine boundary before committing
to a consensus dependency. Introduce a pinned Bitcoin Core reference harness.

Exit evidence:

- Valid and invalid fixtures cover size limits, malformed encodings, witness/txid
  distinctions, proof-of-work targets, historical activation boundaries, and
  representative mainnet transactions and blocks with recorded provenance.
- Property tests and fuzz targets exercise parsers and arithmetic boundaries.
- Differential failures against the reference are reproducible and explained.
- This milestone reports exactly which checks exist; it does not label headers-only
  operation as full validation.

## 2. Chainstate, contextual validation and recovery

Implement transaction/script validation, UTXO transitions, contextual block rules,
activation logic, atomic state updates, undo data, competing branches, and reorgs.
Select storage using measured read/write, recovery, and resource behavior. Add
offline block import so correctness can be exercised independently of networking.

Exit evidence: deterministic replay; invalid-input rejection; matching reference
accept/reject decisions; consistent UTXO/state results; connect/disconnect/reconnect
tests; fault injection for interrupted writes, disk exhaustion and corrupted
reconstructible indexes. Historical rule coverage is tracked explicitly.

## 3. Peer networking and synchronization

Implement bounded framing, peer lifecycle, discovery, timeouts, bans/eviction,
header and block acquisition, initial download, restart/resume, and ongoing sync.
Treat peer-provided data as untrusted and isolate limits per connection and globally.
Bring up regtest, then signet/testnet4 and mainnet with the required network rules.

Exit evidence: multi-node synchronization and reorg tests; malformed/stalling peer
tests; bounded queues; recovery after disconnection/restart; independently validated
historical mainnet replay and sustained synchronization before claiming mainnet readiness.
The GUI shows actual progress, peer details and observation times.

## 4. Mempool, relay and policy explanations

Add transaction admission, dependency/package handling, fee accounting, replacement,
eviction, transaction relay, and reorg reconciliation. Separate consensus results
from local policy outcomes in types, APIs and UI. Add shadow-policy evaluation on
locally observed traffic without changing live admission or block validity.

Exit evidence: adversarial package/replacement workloads, bounded memory, reference
interoperability, replayable decision reasons, and acceptance of valid blocks even
when they contain transactions rejected by local relay policy.

## 5. Wallet connectivity and everyday operation

Define an authenticated, versioned control interface and an explicit tested subset
of Core-compatible RPC. Add descriptor watch-only scanning, wallet broadcast and
fee information, followed by Electrum and compact-filter services where specified.
Keep signing keys outside the chain daemon. Add archival/pruned modes, rescan and
historical-data recovery plans, service isolation and independent index progress.

Exit evidence: documented wallet integration tests; per-service permissions and
resource limits; pruning/recovery tests; reconnect/rescan behavior; useful headless
operation and desktop workflows driven by the same commands and snapshots.

## 6. Privacy, resilience and release qualification

Implement enforceable traffic profiles, Tor/I2P routing as selected, transaction
origin privacy, no silent route fallback, peer-diversity diagnostics, and redacted
bounded diagnostics. Verify upgrade/rollback and backup/restore behavior for the
actual data formats. Build reproducible release and dependency review processes.

Exit evidence: network-capture tests of each privacy profile, failure-path tests,
long-running resource and recovery workloads, supported-platform release checks,
and documented validation coverage and limitations. Primary-node readiness requires
the combined evidence from milestones 1–6, not just a successful regtest demo.

## 7. Continued improvements

Optional mining/template services and Stratum V2 integration, shadow reference
verification, deep replay and profiling, alternative storage, Utreexo, SwiftSync,
Silent Payments scanning, and succinct proofs are research directions. Evaluate
each against equivalent guarantees and an explicit baseline. Keep the conventional
full-validation path usable as the project explores alternatives.

Use the [experiment template](experiments/TEMPLATE.md). Publish negative results and
reusable implementations. Update this roadmap and the capability inventory only
when the corresponding behavior and acceptance evidence exist.

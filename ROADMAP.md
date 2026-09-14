# Roadmap

Build a complete, publicly usable Bitcoin node and pursue leadership across every
important dimension of node operation. Core compatibility and lightweight operation
are foundations to exceed, not the ceiling. The ambition includes expert headless
use, a capable egui desktop, constrained devices, wallet infrastructure and mining.

This roadmap has two parts: **integration gates** that establish a working node,
and **engineering and research workstreams** that pursue advantages throughout
development. Research starts as soon as its prerequisites exist. It is not a final
miscellaneous milestone after feature parity.

The [scorecard](docs/SCORECARD.md) defines workloads, operating profiles, stretch
targets, comparison rules and evidence. All node-performance results are currently
**unmeasured**. Milestones are acceptance gates, not calendar promises or claims
that unresolved research will succeed.

## Integration gates

### G0 — Application foundation (current)

- [x] Public-use project under Connor Avila's GitHub account, independent of Avila Labs; MIT license.
- [x] Rust workspace, pure shared contracts, CLI and native egui shell.
- [x] Strict configuration parsing, separate network data paths, bounded local events.
- [x] Explicit capability inspection and startup refusal for absent node subsystems.
- [x] Committed dependencies and CI for formatting, linting, tests, docs and CLI smoke checks.
- [x] Supplied branding, searchable/resizable tables, keyboard navigation, egui development tools.
- [x] Light, Dark and true Black appearance with remembered theme and scale.
- [x] Full-node scope, egui capability plan and measurement requirements.
- [ ] Native packaging and interaction validation across intended desktop platforms.

Evidence: workspace checks and application interaction tests pass. Unknown chain
measurements remain unknown. This gate establishes an application, not a Bitcoin node.

### G1 — Consensus fixtures, reference adapter and measurement harness

- [ ] Record the validation-engine decision, trusted dependencies and extraction boundaries.
- [x] Implement bounded decoding, transaction/witness identities, headers, target arithmetic,
  proof of work, linkage, chainwork and explicit network parameters.
- [x] Inventory historical and activated consensus rules with valid/invalid fixtures,
  activation context and provenance; start mainnet cases immediately.
  See docs/RULE_INVENTORY.md and fixtures/manifest.json.
- [x] Add a pinned Core reference adapter, parser/arithmetic fuzzing and disagreement artifacts.
  See tools/check_headers_core.py (adapter + per-run reference pin and artifact)
  and fuzz/ (libFuzzer targets).
- [ ] Implement the scorecard runner: exact manifests, raw measurements, correctness checks,
  cold/warm workloads and reproducible reference runs.
- [ ] Record baseline measurements before selecting hot-path layouts or storage defaults.

Evidence: implemented checks are enumerated, invalid cases fail for the expected
reason, reference discrepancies have reproducible cases, and another developer can
repeat measurements. Header validation alone is not labeled full validation.
Workstreams W1–W4 begin here; security/privacy threat models begin with the interfaces.

### G2 — Offline full validation and durable chainstate

- [ ] Implement Script and contextual transaction/block rules, UTXO transitions,
  historical activation behavior, competing chains and deterministic fork selection.
- [ ] Support offline block import, atomic commits, undo, reorgs and resumable replay.
- [ ] Compare storage candidates on real state access, write amplification and recovery.
- [ ] Separate active tip, complete validation coverage, index coverage and assumptions.
- [ ] Validate historical mainnet data and adversarial fixtures, including connect,
  disconnect and reconnect under interrupted writes, disk exhaustion and corruption.

Evidence: reproducible accept/reject and state comparisons, correct reorg behavior,
recoverable commits and a published initial full-validation performance profile.
Storage and synchronization research can use this implementation before P2P is ready.

### G3 — Independent network synchronization

- [ ] Implement bounded P2P framing, discovery, lifecycle, acquisition and restart/resume.
- [ ] Enforce per-peer and global budgets, timeouts, eviction and cancellation.
- [ ] Exercise regtest, signet, testnet4 and mainnet with their required rules.
- [ ] Implement selected transport/privacy constraints together with traffic paths.
- [ ] Add real sync, peer and resource observations to CLI and GUI.

Evidence: multi-node sync/reorg tests, malformed and stalling peers, unavailable
privacy routes, interrupted downloads and sustained synchronization all have tested
outcomes. Mainnet readiness requires independently validated history and continuing
operation. Compare complete initial download and catch-up, not only local replay.

### G4 — Complete everyday node and service workflows

- [ ] Implement mempool admission, packages, replacement, eviction, relay and reorg reconciliation.
- [ ] Provide replayable policy explanations and isolated shadow-policy evaluation.
- [ ] Deliver authenticated/versioned control, a tested Core RPC compatibility matrix,
  watch-only descriptors, wallet broadcast, fee information and scoped service access.
- [ ] Deliver Electrum/compact-filter services with tested clients and explicit index coverage.
- [ ] Support archival/pruned operation and verified historical reacquisition for rescans.
- [ ] Integrate mining templates and selected Stratum V2 workflows behind optional services.
- [ ] Provide backup/restore, migration/rollback, resource presets and actionable recovery.

Evidence: documented end-to-end wallet, mining, pruning, reorg, service-isolation and
recovery tests. Headless and desktop workflows use the same commands and state.
An unsupported API or incomplete scan reports its actual status.

### G5 — Public release qualification

- [ ] Qualify supported Linux, Windows and macOS builds and selected x86-64/ARM64 hardware.
- [ ] Exercise long-running loads, network partitions, resource exhaustion and crash recovery.
- [ ] Publish scoped privacy/security evidence, independent review findings and fixes.
- [ ] Verify reproducible release builds, signed artifacts, provenance and dependency/license inventory.
- [ ] Test clean installation, upgrade, rollback and restore with documented compatibility limits.
- [ ] Validate accessibility, keyboard use, appearance, scaling and real operator tasks.
- [ ] Publish the scorecard with successes, regressions, unsupported cases and reproduction data.
- [ ] Establish security reporting, supported-release policy, contributor guidance and release ownership.

Primary-node readiness requires the combined evidence from G1–G5. Release labels
must identify qualified profiles and features. A release can be useful before every
research goal succeeds; releasing it does not mark unfinished leadership goals complete.

## Engineering and research workstreams

Each workstream remains part of the product scope. Optional means the operator can
disable its service or cost; it does not mean the project can ignore that workflow.
Each experiment records a question, entry point, baseline and integration gate.

### W1 — Consensus correctness and assurance

Begin at G1. Build a rule-to-test inventory spanning historical exceptions,
activation boundaries, malformed encodings, arithmetic, Script and chain context.
Combine independent fixtures, differential tests, property testing, fuzzing,
deterministic replay and targeted formal analysis of tractable state machines.
Investigate shadow verification with bounded overhead and independently implemented
checks where they can detect shared mistakes.

Integrate with reproducible agreement and explicit coverage; resolve discrepancies
from rules and evidence rather than majority voting. A clean test corpus cannot
prove absence of consensus bugs. Track both correctness evidence and attack costs.

### W2 — Validation speed, scheduling and energy

Begin at G1 microbenchmarks and G2 replay. Explore compact data layouts, allocation
reduction, context-correct caching, pipelined decoding and validation, bounded
parallel verification, efficient vetted cryptography and adaptive resource budgets.
Preserve deterministic commit ordering and correct cancellation/reorg behavior.
Profile cache misses, disk stalls, contention and energy per completed workload.

Target substantially faster complete verification, lower peak memory and lower
tail latency together. Integrate based on end-to-end gains across hardware and
hostile inputs; a faster isolated primitive is insufficient evidence.

### W3 — Accelerated synchronization with explicit verification

Prototype after G1 fixtures; compare against G2 full replay, then G3 network sync.
Investigate verified hints, parallel historical work and
[SwiftSync's original proposal](https://gist.github.com/RubenSomsen/a61a37d14182ccd78760e477c78133cd),
with the [archived protocol draft](https://github.com/2140-dev/swiftsync-bips) as
additional research context rather than an assumed stable specification.
Evaluate the exact algorithm and checks; different variants can have different
requirements. Record hint production, download, validation, storage and failure costs.

Develop snapshot bootstrapping with separately reported active state and background
validation, informed by [AssumeUTXO's chainstate separation](https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md).
Measure time to usable tip and time to complete historical verification separately.
Corrupt/missing hints, snapshots and interrupted work require tested recovery.
Fewer executed checks must never be presented as faster equivalent full verification.

### W4 — Storage, compact state and low-resource operation

Begin storage experiments at G1 and integrate with G2. Compare hot/cold state
separation, cache policies, sequential writes, compression, indexes and undo formats.
Pursue low write amplification, bounded growth, fast restart, reduced wear and
explainable repair across archival, pruned and compact modes.

Prototype [Utreexo-style accumulators](https://eprint.iacr.org/2019/611), proof
verification/caching and proof-provider behavior. Smaller local state can introduce
proof traffic and helper costs; measure both. Compare with
[Floresta's reusable Rust node and wallet services](https://github.com/getfloresta/Floresta).
Qualify constrained ARM devices and slow storage, then investigate smaller/mobile
deployments with their power, background-execution and connectivity constraints.

Integrate only with reorg, restore and historical-data availability behavior defined.
Archival retention and minimum local storage are separate profiles of the same node.

### W5 — Efficient, resilient P2P and relay

Design budgets at G1 and implement with G3. Explore peer-aware acquisition,
compact-block efficiency, reduced redundant transaction announcements, adaptive
backpressure and fair scheduling. Evaluate encrypted transport, peer diversity,
eclipse resistance, partition recovery and adversarial resource asymmetry.
[BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) is a transport
reference; transport encryption alone does not conceal network endpoints.

Integrate with interoperability and controlled-topology evidence: propagation
latency distributions, useful versus redundant bytes, CPU per rejected input,
connection churn and recovery. Count overhead across the topology as well as locally.

### W6 — Enforced privacy and service security

Start at G1 interface design, before traffic exists. Model each traffic purpose,
permission and failure route. Implement selected Tor/I2P routing, transaction-origin
privacy, fail-closed behavior, scoped authentication, service isolation and bounded,
redacted diagnostics. Include discovery/DNS, retries, wallet/index requests and
future update mechanisms in the model. Keep local operation independent of accounts
and hosted services.

Integrate with network-capture and fault-injection tests, forbidden-route checks,
permission tests and a published threat model. Explore origin-linkability under
declared adversaries; zero observed leaks in a test is not universal anonymity.
Privacy and security remain release requirements across all later workstreams.

### W7 — Mempool economics and explainable policy

Prototype dependency graphs after G1; integrate with G4. Develop bounded package
admission, replacement and eviction, cluster-aware economic evaluation, incremental
updates and consistent reorg handling. Record why a transaction was accepted,
rejected, replaced or evicted, with bounded explanation costs.

Compare shadow policies on reproducible traffic without changing live consensus
or admission. Integrate with adversarial package tests and measurements of memory,
admission/eviction latency, relay behavior and template quality. Local observations
must not be labeled a view of the entire network mempool.

### W8 — Wallet infrastructure, indexing and private discovery

Design coverage/permission contracts at G2; integrate with G4. Deliver descriptor
watch-only scanning, a documented RPC surface, Electrum, compact filters, broadcast
and fee information. Test actual wallet clients and hardware-wallet companion
workflows while keeping signing keys outside the chain daemon.

Optimize index sharing, incremental scans, multi-wallet isolation, cancellation
and historical reacquisition on pruned nodes. Investigate Silent Payments scanning
with explicit CPU and privacy budgets. Explain scan coverage, reorg invalidation
and recovery plans. Integrate with measured query/rescan performance and complete
end-to-end wallet recovery; an unsearched interval must not appear as an empty balance.

### W9 — Mining and template quality

Prototype once G2 can validate candidate blocks; integrate with G4's mempool.
Build low-latency valid templates, incremental refresh, package selection and
reorg-safe work updates. Support solo operation and investigate compatible
[Stratum V2 job declaration](https://stratumprotocol.org/specification/06-job-declaration-protocol/)
and template-provider integration.

Measure template validity, fees selected from identical transaction sets, refresh
latency and stale work under load. Compare selection quality against bounded small
instances with known optima and realistic reference workloads. Pool-side support
and traffic costs must be explicit in interoperability results.

### W10 — Resilience, recovery and operator control

Begin failure models at G1, inject storage faults at G2 and extend through G5.
Build durable transitions, corruption detection, resumable reconstruction, precise
disk/resource budgets and explainable recovery. Test abrupt termination, partial
writes, disk full, missing history, partitions, index failures and upgrade failures.
Separate reconstructible data from state that cannot simply be downloaded again.

Provide actionable diagnostics, validated backup/restore, configuration diffs and
format-aware migration/rollback. Measure recovery time, replayed work, downtime,
data correctness and operator steps. Qualify unattended operation with long soaks
and enforced resource limits; a graceful restart test is not crash qualification.

### W11 — egui, observability and everyday usability

Started at G0 and advances with each real subsystem. Use virtualized tables,
search/filter, keyboard actions, contextual explanations and accessible controls.
Add real time-series plots, latency histograms, linked inspectors, dependency and
reorg graphs, pan/zoom, bounded replay timelines and detachable viewports when their
data sources exist. Follow the [egui plan](docs/GUI.md) for relevant demo capabilities.

Provide clear resource/privacy profiles and recovery workflows, Light/Dark/Black,
scaling, reduced motion and exportable evidence. Measure frame/input latency and
idle overhead with large datasets, plus real task completion, errors and keyboard/
screen-reader access. The GUI must remain responsive during sync, scan and failure;
headless operation retains the same control and observability semantics.

### W12 — Public distribution, maintainability and reuse

Begin with G0's workspace and continue through G5. Develop documented component
APIs, useful contribution tasks, reproducible builds, portable packaging and tested
upgrade/restore paths. Track dependencies and licenses, review trust boundaries,
and make release provenance independently checkable.

Measure supported-platform coverage, reproducibility, build/resource costs and
time to diagnose and fix failures. Provide security reporting and maintenance
documentation. Publish reusable components and negative findings as well as wins;
the integrated public node remains the deliverable.

### W13 — Proof-assisted verification and further frontier research

Start a bounded rule-coverage and cost investigation after G1; integration depends
on G2's complete reference path. Explore succinct proofs, independently checkable
sync artifacts and verified parallel/distributed work. Evaluate verifier size,
prover resources, availability, cryptographic assumptions, historical rule coverage,
chain selection and reorg behavior.

[ZeroSync's public demo verifies headers and no transactions](https://zerosync.org/demo/).
A header proof is not evidence of complete transaction/state validation. Any Avila
proof mode must state exactly what it establishes and retain a conventional replay
option. Publish feasibility failures; keep successful research eligible for product
integration without promising an unresolved cryptographic result.

## Next implementation slice

The next code milestone is G1: rule/fixture inventory, bounded header decoding and
proof-of-work/chainwork checks, a pinned reference adapter, and reproducible baseline
measurements. This gives later optimization claims something concrete to improve.
Choose the first storage and historical-validation experiments from those results.

For every later slice, identify its integration gate, workstream, scorecard rows and
acceptance evidence. Use the [experiment template](experiments/TEMPLATE.md), publish
regressions, and update implemented capabilities only after the behavior exists.

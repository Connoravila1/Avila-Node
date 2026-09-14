# Performance and quality scorecard

**Status: measurement specification; no Avila node benchmarks have run.** The
application foundation's tests do not establish consensus correctness, node
performance, privacy or primary-node readiness. A runnable harness is part of G1
in the [roadmap](../ROADMAP.md).

The aim is to lead the strongest reproducible alternatives across all relevant
operating profiles. Publish each result independently. Do not collapse correctness,
privacy, latency and memory into a weighted score that hides a failure.

## Operating profiles

Profiles describe required work and guarantees, not simply a product name. Storage,
services, resource limits and privacy are separate choices that can be combined.

| Dimension | Required comparisons |
| --- | --- |
| Storage and verification | Archival full validation; pruned full validation; compact/accumulator validation with exact proof and data requirements |
| Services | Base node; descriptor wallet backend; Electrum/index server; compact-filter server; mining/template backend |
| Hardware | Constrained ARM64; ordinary x86-64 desktop; multi-core server; slow and fast storage; lower memory limits |
| Connectivity | Controlled local replay; controlled network sync; bounded/latent/lossy links; interrupted and long-offline catch-up |
| Privacy | Explicit clearnet, selected Tor/I2P routes, transaction-broadcast constraints and failure behavior |
| Workload | Idle, historical initial sync, current-tip validation, reorg, transaction/package load, query/rescan, crash/recovery |

Freeze actual devices, RAM budgets, peer counts, datasets, service options and routes
in each experiment. A label such as “small ARM node” is not a reproducible machine
specification. Publish defaults and reasonably tuned configurations separately;
give references an equal tuning budget. Identify unsupported combinations instead
of silently removing them from the comparison.

Snapshot-assisted startup has two milestones: usable active state and completed
historical validation. Proof-assisted modes additionally state their rule coverage,
cryptographic assumptions and data availability. These modes get separate rows when
their guarantees differ from conventional replay.

## Baseline selection

Use a pinned Bitcoin Core release for relevant validation, storage, P2P, mempool,
RPC and mining behavior. At the September 13, 2026 scope review,
[Core 31.1 is a published release](https://bitcoincore.org/en/releases/31.1/).
Resolve and record the exact release, commit and build when an experiment begins;
update comparisons as references improve.

Use a pinned [Floresta](https://github.com/getfloresta/Floresta) revision for compact
validation, resource use, reusable-node and wallet-service comparisons. Its current
documentation describes Utreexo, a watch-only wallet, Electrum and a
rust-bitcoinkernel validation boundary. Match actual enabled behavior and distinguish
independent implementations from shared validation code.

The surveyed field — including btcd, Gocoin, libbitcoin, Knots and specialist
services — with per-row reference assignments and exclusion reasons lives in
[docs/NODE_LANDSCAPE.md](NODE_LANDSCAPE.md). Add specialist indexers, wallet
backends, mining services and storage implementations where they provide a
stronger applicable comparison. A benchmark against Core and
Floresta alone cannot establish leadership over every alternative. Record the search
date, inclusion criteria and reasons for exclusions in each report.

## Metric inventory and initial targets

The numbers below are **proposed engineering stretch targets**, not measurements,
forecasts or maximum ambition. They make the first optimization program concrete.
Evaluate them against the best measured comparable reference for that row and
hardware profile. Revisit targets openly after baseline measurements; preserve the
original targets and reasons for changes. A successful row does not make the whole
node best, and missing a stretch target does not invalidate an otherwise useful release.

| ID | Dimension and measurement | Initial objective | Evidence / current result |
| --- | --- | --- | --- |
| C1 | Consensus acceptance, resulting state, historical/activation rule coverage | Zero unexplained discrepancies in the declared corpus; all required rules covered before readiness | Header-rule layer done: [rule inventory](RULE_INVENTORY.md), fixture corpus with provenance, differential adapters (`tools/check_headers_core.py`, `tools/check_blocks_core.py`) at zero mismatches (1,070 block submissions: regtest corpus, real fixtures, 501-block mainnet + 301-block signet segments), libFuzzer harness (`fuzz/`) |
| C2 | Security and adversarial resource use: CPU, memory, disk and queues per hostile workload | Enforce every declared limit, isolate optional services and close discovered failures | Threat model, fault tests, review scope and unresolved findings; **unmeasured** |
| P1 | Full initial validation: elapsed time, CPU time, work/s | Aim for at least **2× throughput / half elapsed time** with the same checks; network-constrained results reported separately | First block-level baseline exists: `tools/scorecard_blocks.py` replays the blk.dat segments through `Chainstate` vs `submitblock` on fresh daemons — first run: mainnet 0..=500 in 0.01s (ref submit-phase 0.18s), signet 0..=300 in 0.03s (ref 0.14s), RSS 17.8MiB vs 56MiB; artifacts in `target/scorecard/` record the full manifest. The reference figure includes its disk writes + RPC overhead, per protocol |
| P2 | Current-tip block validation and reorg processing: p50/p95/p99 latency | Aim for **half p95 latency**, without worse p99 behavior or reduced checks | Ordinary and worst-case blocks/reorgs under background load; **unmeasured** |
| P3 | Peak and steady memory: process RSS, private allocations, page cache and helper processes | Aim for **half peak working memory** within a matched profile while improving time | Whole-process/system measurements, cache and allocator breakdown; **unmeasured** |
| P4 | Storage: chainstate/index/undo bytes, total footprint, reads/writes, write amplification | Aim for **half mutable-state/index overhead and write amplification**; compare retained block bytes separately | Identical coverage/retention, peak migration space, compaction and wear proxies; **unmeasured** |
| P5 | Network: useful/total bytes, redundancy, proof/hint bytes, propagation latency | Aim for **half redundant relay traffic** without sacrificing propagation or peer resilience | Controlled topologies, churn, loss and complete helper traffic; **unmeasured** |
| P6 | Energy: joules per fixed fully verified workload; idle watts | Aim for **half verification energy** and minimal idle work | Calibrated measurement with device scope and idle baseline; **unmeasured** |
| P7 | Wallet/index services: p50/p95/p99 query latency, rescan duration, rebuild cost | Aim for **half p95 query latency and rescan time** at matched index coverage/resource budgets | Actual clients, concurrent requests, pruning/reorg and old-wallet recovery; **unmeasured** |
| P8 | Mempool: admission/replacement/eviction latency and bytes per transaction/package | Beat the strongest comparable profile in tail latency and memory while handling hostile dependencies | Identical traffic, policy and retention; shadow results separate; **unmeasured** |
| P9 | Mining: template validity, selected fees, build/refresh latency, stale work | All templates valid; match or improve selected fees and aim for **half p95 refresh latency** | Identical mempool, small known-optimum cases and realistic workload replays; **unmeasured** |
| Q1 | Privacy: forbidden-route observations and origin-linkability under a defined adversary | Zero forbidden-route observations in qualification tests; reduce measurable linkability under matched conditions | Captures including DNS/retries/failures and explicit inference limits; **unmeasured** |
| Q2 | Recovery: restored state, downtime, replayed work, manual steps, upgrade success | Correct recovery for every declared fault; aim for **half p95 recovery time** with simpler operator steps | Abrupt faults, disk full/corruption, backup restore, format migration/rollback; **unmeasured** |
| Q3 | GUI: frame time, input response, idle CPU/memory, large-table responsiveness | Initial budget: **p95 frame ≤16.7 ms**, **p99 input response ≤50 ms** on a declared reference desktop; no continuous repaint while idle | Native traces during sync/scan/large-data interaction; shell smoke checks only, **unmeasured** |
| Q4 | Usability/accessibility: completion, errors, recovery, keyboard and screen-reader coverage | Complete every supported essential task; fewer errors and shorter completion than comparable workflows | Declared participants/tasks, all themes/scales, platform assistive technology; **unmeasured** |
| Q5 | Interoperability and distribution: tested APIs/clients/platforms, install/upgrade success | All advertised workflows qualified, explicit compatibility matrix and unsupported cases | Client suites, native packages and release qualification; foundation Linux checks only |
| Q6 | Maintainability and supply chain: reproducible builds, reviewability, build cost, repair effort | Reproducible release artifacts, documented component contracts and tested release/recovery procedures | Independent rebuilds, dependency inventory, scoped reviews, reproduction reports; **not qualified** |

The memory and speed targets are intended to be pursued together, not won by
unlimited caching in one run and disabling services in another. Publish all resource
dimensions for each configuration. Raw archival block retention and original block
transfer volume are not assumed reducible by the same factor as implementation
overhead. Correctness and privacy are qualification constraints with scoped evidence,
not claims that “twice as secure” or “100% anonymous” can be derived from these tests.

## Measurement protocol

1. **Register the comparison.** Identify roadmap workstream, scorecard rows,
   hypothesis, outcome that would disprove it, baseline selection, resource budgets
   and regression tolerances before evaluating the candidate.
2. **Freeze the manifest.** Record source commits, lockfiles, compiler/build flags,
   CPU/storage/firmware, OS, power settings, limits, network topology, configuration,
   dataset provenance/checksums and reproduction commands.
3. **State equivalent work.** Enumerate executed validation checks and activation
   context, assumed-valid/snapshot settings, indexes, retention, privacy routes,
   mempool policy and output coverage. Run conventional full historical validation
   with historical Script checks enabled on both sides when making that claim.
4. **Verify outputs first.** Compare accept/reject results, canonical state where
   representations permit it, observable semantics and recovery outcomes. Different
   state representations need a specified equivalence check. Do not resolve a
   reference discrepancy by making Avila copy an unexplained result.
5. **Measure complete workloads.** Report cold and warm runs separately, local replay
   and network sync separately, and first-use preparation separately from steady
   state. Include proof/hint creation, index construction and external helpers.
6. **Control uncertainty.** Use repeated runs, a documented warmup/run-order policy,
   distributions and uncertainty estimates. Give sample counts and failure counts.
   Predefine outlier handling; publish unsuccessful and interrupted trials.
7. **Expose total costs.** Report local and required helper CPU, RAM, storage,
   bandwidth, energy and availability. State any amortization assumptions. A smaller
   client is not automatically a cheaper overall system.
8. **Stress the candidate.** Include malformed/hostile inputs, churn, partitions,
   constrained hardware, full disk, interrupted writes, reorgs and concurrent services
   as appropriate. Check resource limits and p99 behavior, not only average speed.
9. **Publish reproducible evidence.** Store bounded redistributable fixtures and
   manifests in Git; publish checksummed larger artifacts separately. Remove private
   traffic, wallet data and secrets. Provide commands and raw results sufficient for
   someone else to rerun the experiment.
10. **Make a scoped decision.** Record integration, revision or rejection. Report
    wins, losses, unsupported cases, limitations and any changed guarantees. Preserve
    prior results when updating reference versions.

Use the [experiment template](../experiments/TEMPLATE.md). No benchmark number should
enter the README or GUI as a capability until its implementation and evidence exist.

## Reporting leadership

A valid statement names the metric, dataset, profile, hardware, reference revisions
and uncertainty: for example, “lower peak RSS on workload X with all declared checks
enabled.” Do not invent a representative number before running the workload.

For each release, publish a matrix of **leads / comparable / behind / unsupported /
unmeasured**, with links to underlying experiments. Report qualifications separately
from relative rankings. Keep weaker cases visible and prioritize work against them.
The goal is continuing improvement across the whole matrix; a claim of being best
by every possible metric, configuration and future comparison cannot be established.

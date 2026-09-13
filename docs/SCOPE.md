# Avila Node scope

## Purpose

Build a complete Bitcoin full node, in Rust, with excellent headless operation and
a native egui application. A person should eventually be able to choose Avila Node
as their primary node, independently of another node implementation or hosted service.
That is a target to demonstrate through implementation and testing, not a statement
about the current scaffold's capabilities.

The project is hosted under Connor Avila's personal GitHub account, under the MIT
license, independent of Avila Labs. It is intended for other people to use once
ready. Personal describes account ownership; it does not set a feature, quality,
maintenance, or distribution ceiling. Experimental describes the current maturity
and novel implementation ideas. The integrated node is the primary deliverable;
other projects incorporating useful components or findings is an additional success.

## What leadership means

The ambition is to lead across correctness, security, validation speed, memory,
storage, bandwidth, energy use, privacy, resilience, wallet and mining services,
interoperability, usability, accessibility, and maintainability. Matching Core's
functionality or Floresta's resource use is an intermediate comparison, not the
destination. The [roadmap](../ROADMAP.md) specifies the engineering and research
program; the [scorecard](SCORECARD.md) defines how results will be judged.

Different operating requirements need different configurations of one coherent
node: archival and pruned storage, compact verification, wallet infrastructure,
mining, constrained hardware, and privacy-sensitive operation. Comparisons must
match guarantees and count total costs, including required helpers. Pursue better
tradeoffs across these profiles and make configuration changes understandable.
No single aggregate score should hide a regression or an unsupported workflow.

Best by every metric is the direction of work, not a provable permanent ranking.
Correctness and privacy evidence has a stated scope; faster code does not compensate
for missing checks. There are no measured node-performance results in this scaffold.

## Product requirements

- Independently validate Bitcoin blocks and transactions, select the strongest
  valid chain, synchronize, persist state, recover, and handle reorganizations.
- Support practical node operation: peer management, mempool and transaction relay,
  resource limits, pruning/archival operation, diagnostics, and wallet connectivity.
- Expose what has actually been verified: active and historically validated state,
  assumptions, index and wallet scan coverage, and freshness of observations.
- Enforce operator-selected privacy constraints, including failure behavior when a
  requested route is unavailable. Explain observable limits of those guarantees.
- Keep local relay/mining policy separate from Bitcoin block-validity rules.
  Explain decisions and allow meaningful comparisons against shadow policies.
- Make recovery, resource use, permissions, and interoperability inspectable.
- Use egui as both a practical operator interface and an instrument for explaining
  node behavior, comparing approaches, and inspecting evidence.
- Make improvements measurable and components reusable without requiring the GUI.
- Deliver documented, accessible public releases, installation and upgrade paths,
  recovery procedures, compatibility tests, and a sustainable contribution process.
- Develop resource-efficient wallet and mining services as first-class workflows,
  with explicit permissions and optional operating costs.

## Engineering principles

Use a deterministic validation core with explicit inputs and typed results.
Keep filesystem, network, clock, randomness, and presentation concerns at explicit
boundaries. Use reviewed cryptographic implementations. Choose data layouts and
optimizations from measured workloads rather than blanket rules about allocation,
methods, dependencies, or record sizes.

Represent unknown measurements as unknown. A configured network is not a connected
network, a known header is not a validated block, a snapshot-backed tip is not
complete historical validation, and an index's answer must identify its coverage.

Cache only appropriately scoped results. Transaction identity, witness identity,
signature-check context, and chain-dependent validity need distinct treatment.
Reorganizations must invalidate or update affected conclusions.

Maintain owner control: local operation, optional services with bounded resources,
deliberate upgrades, and no required vendor account or cloud dependency.

## Research alongside implementation

Shadow validation, deterministic replay, policy comparison, advanced wallet scanning,
mining services, accumulator storage, accelerated synchronization, and proof-assisted
verification have explicit workstreams and entry points in the roadmap. Begin their
experiments when the required fixtures and interfaces exist; do not defer every
potential advantage until a conventional node is finished. Each needs a hypothesis,
assumptions, a runnable comparison, and acceptance evidence. Integrate successful
approaches into the complete node while retaining a usable full-validation path.

## Decisions still requiring engineering evidence

The consensus implementation strategy and reference adapter, storage engine and
crash-consistency design, asynchronous runtime, authenticated control protocol,
wallet API compatibility surface, and optional service isolation are not selected
by the scaffold. Record those choices when the relevant milestone begins, with
alternatives and experiments. Linux is the first local validation environment;
Windows and macOS portability are intended and require their own validation.

## Source of the brief

Recovered from the owner's [shared planning conversation](https://chatgpt.com/share/6aa72092-7328-83ea-9cb0-9c7aefe2b243)
and supplied PDF on September 13, 2026, with the owner's final clarification that
the deliverable must be a complete node usable as a primary node. The earlier
Zatoshi attachments were not supplied in this repository; the conversation's
discussion of them is context, not an independently audited specification.

The owner's latest clarification on September 13, 2026 confirms public use under
the personal GitHub account and ambition beyond Core/Floresta parity across all
metrics. Instructions also require consolidation on `main`, the supplied orange
AN logo, Light/Dark/Black appearance, and deliberate use of egui's relevant
capabilities. The planning conversation's external research claims must be rechecked
before they become implementation requirements.

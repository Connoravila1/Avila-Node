# Avila Node scope

## Purpose

Build a complete Bitcoin full node, in Rust, with excellent headless operation and
a native egui application. A person should eventually be able to choose Avila Node
as their primary node, independently of another node implementation or hosted service.
That is a target to demonstrate through implementation and testing, not a statement
about the current scaffold's capabilities.

This is Connor Avila's personal project, under the MIT license, independent of
Avila Labs. Experimental describes its maturity, novel implementation ideas, and
the maintenance assurances a personal project can offer. The integrated node is
the primary deliverable. Other projects incorporating useful components or findings
is also a successful outcome.

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

## Longer-term directions

The complete node provides the foundation for optional shadow validation, event
replay, policy comparison, advanced wallet scanning, mining services, accumulator
storage, accelerated synchronization, and proof-assisted verification. Each needs
its own question, assumptions, implementation, comparison, and acceptance evidence.
These directions do not substitute for the working full-node path.

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

The current instruction adds consolidation on `main`, the supplied orange AN logo,
and deliberate use of egui's relevant capabilities. The planning conversation's
external research claims must be rechecked before they become implementation requirements.

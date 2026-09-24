# Verification-transparency ledger — `getvalidationreport`

**Date:** 2026-09-24 · **Status:** ADOPTED (core record + RPC)

## Hypothesis

A node should report its own trust state: which heights it verified itself,
which it assumed under a commitment, and the progress converting assumed into
proven. Nobody ships inspectable trust — `getchainstates` reports *that* a
snapshot is unverified, not *what fraction* of the chain is assumption.

## What was built

- `Chainstate::validation_report()` → typed `ValidationReport`:
  - `connected_height` — every script `0..=h` checked
  - `header_height` — PoW/structure-verified tip
  - `snapshot: Option<SnapshotCoverage>` — base height/hash, the pinned
    `hash_serialized` commitment (sole trust anchor), `replayed_height`,
    `verified`
  - `verified_fraction` — `(verified_or_proven) / connected`; `1.0` on a
    full-validation node
- RPC `getvalidationreport` (Avila-specific; no Core equivalent, named so it
  can't collide): emits the record plus `assumed_heights` /
  `unproven_heights` ranges for the snapshot prefix.
- Two tests: snapshot path (fresh → replayed → verified transitions) and
  plain-node full coverage.

## Semantics (the honest part)

- Heights strictly above the snapshot base were connected normally — verified.
- Heights `1..=replayed` are *proven* — background validation checked them.
- Heights `(replayed, base]` are *assumed* — taken on the commitment, replay
  pending. `verified_fraction` counts only verified+proven.

## Verdict

Cheap, unique, on-brand. The differentiator is now a queryable fact:
`bitcoin-cli getvalidationreport` answers "what did this node actually check?"
No other implementation surfaces assumed-vs-proven coverage as a typed value.

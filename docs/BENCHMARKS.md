# Benchmarks — methodology and comparison baseline

Status: active spec. Every performance or resource claim in this repo
must name its baseline and its fixture — an un-baselined number is a
mechanism observation, not a win.

## The baseline

- **Core reference version: 31.1.** Policy is ported from v31.1;
  consensus comparisons must not cite older releases. Knots policy
  divergence is measured live via the shadow observatory
  (`getmempoolinfo.shadow`) — that is our standing cross-implementation
  dataset.
- **Architectural comparator for SwiftSync-style claims: Floresta.**
  Its utreexo path is the closest public analogue; where a Floresta
  number exists, cite it, not a Core default.
- **Fixture: real chain data, never synthetic.** The signet blk files
  (~5.6 GB, ~324k blocks) are the canonical replay fixture. Synthetic
  fixtures are for unit tests only — they cannot support a claim.

## Claim tiers (what a result may say)

| Tier | Requirement | What the claim may say |
|---|---|---|
| Mechanism | Unit/integration test or fixture replay | "the property holds" — e.g. cell-aligned writes, audit catches drift, aggregate verifies |
| Fixture-measured | Named fixture + harness in `examples/` | "N bytes / T seconds on fixture X" — absolute, not comparative |
| Comparative | Same fixture, same machine, Core 31.1 baseline run | "M× vs Core 31.1 on fixture X" — the only tier allowed to say *better* |

Today's evidence is almost entirely Mechanism + Fixture-measured.
No Core-31.1 baseline run exists in the repo yet — the first
comparative number must be produced before any speed claim lands
in docs or release notes.

## How to run a Core baseline

```
# Same machine, same fixture. For connect/write cost the honest
# Core comparison is a reindex-chainstate over the signet fixture,
# or an assumeutxo load — measure with the OS page cache cold+warm:
bitcoind -signet -datadir=/tmp/core-baseline \
         -connect=0 -printtoconsole &
# Then: reindex-chainstate=1, or loadtxs/assumeutxo for snapshot paths.
# Record: wall clock, peak RSS, bytes written (du + blk/rev/index).
```

Kill-switch on comparability: if the fixture or machine differs, the
numbers are not comparable — publish both runs' environments.

## Honest-statement rules

- "N% of creates die in-window" (SwiftSync, #31) is a *property of the
  chain*, measured on real data — valid as fixture-measured, not a
  speed claim until a write-path baseline exists.
- Privacy claims require the PRIVACY_MATRIX test cell or the 24h
  capture artifact — never "should be private".
- Fingerprint claims (#38) run the published taxonomy against our
  own construction — we measure ourselves before claiming mimicry.
- Report the environment: CPU, RAM, disk class, and whether tmpfs
  was involved (the memory incident showed tmpfs skews everything).

## Known open measurements

- Core 31.1 IBD write-bytes baseline on the signet fixture (the number
  SwiftSync's 67%-churn figure needs to become a comparative claim).
- `connect_bench` end-to-end wall-clock vs Core `reindex` on the same
  blocks.
- avila-p2p examples exist (`erlay_bench`, `peer_probe`) but no
  sustained-throughput comparison vs a Core peer yet.

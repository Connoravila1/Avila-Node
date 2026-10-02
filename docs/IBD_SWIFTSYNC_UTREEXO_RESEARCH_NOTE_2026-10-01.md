# IBD research note: SwiftSync + Utreexo

Recorded: 2026-10-01. Status: external research and a proposed next experiment;
no new benchmark or implementation is claimed here.

## Why keep this on the IBD roadmap

Bitcoin Optech's [September 18 newsletter](https://bitcoinops.org/en/newsletters/2026/09/18/)
links to Davidson Souza's [implicit-deletion proposal](https://delvingbitcoin.org/t/implicit-deletions-and-improvements-in-utreexo-ibd/2881).
It directly concerns the working-set problem described in our
[September 29 wall analysis](../experiments/2026-09-29-ibd-wall-analysis.md).

The important opportunity is to avoid maintaining the historical working UTXO
set during validation. Faster flushes alone do not provide that benefit.

## What the external work changes

Utreexo keeps compact accumulator roots instead of the full UTXO database,
but normally requires extra inclusion proofs for spends. SwiftSync supplies
hints about which outputs are spent by a fixed checkpoint and checks their
consistency with an order-independent hash aggregate.

The proposal uses those hints to perform **implicit deletions** while building
the Utreexo accumulator. Outputs already spent by the checkpoint need not go
through a later explicit deletion/proof step. This removes the usual deletion
proof requirement during IBD while still computing the final accumulator
locally. Much of block processing can happen in parallel or in arrival order;
accumulator updates retain an ordered worker. Normal Utreexo proof processing
resumes after the hinted checkpoint.

Souza reports bandwidth-limited tests from roughly 30 Mbps to 2 Gbps, including
on a Raspberry Pi. These are the author's reports, not reproduced Avila Node
results or a measured speedup over our node.

**Comparison boundary:** the linked
[Floresta PR #1115](https://github.com/getfloresta/Floresta/pull/1115)
was an open draft as checked on 2026-10-01 and implements assume-valid,
witnessless SwiftSync. It does not establish our objective of checking every
historical signature. The post describes a non-assumevalid version as work
in progress. Near-zero proof overhead does not mean full validation requires
no spent-coin data, or that historical blocks need not be downloaded.

## Our current implementation leaves the main benefit unrealized

At repository revision `9bbd0cfa797bb3c0d5e9f488ea5160ae2f58c357`:

- [swiftsync.rs](../crates/avila-consensus/src/swiftsync.rs) explicitly describes
  keeping full coins in the write-back map throughout the window.
- [connect.rs](../crates/avila-consensus/src/connect.rs) sets `swift_hold` to
  suppress budget-driven flushes, while ordinary coin lookups and mutations
  still use the full set.
- `verify_hints` compares the aggregate and builds a local live-outpoint set
  to check exact survivor equality.

This is useful aggregate tracking and write deferral, but it does not remove
the working UTXO set or its membership lookups.

**Correction to the September 24 interpretation:** the statement in
[our write-elision experiment](../experiments/2026-09-24-swiftsync-write-elision.md)
that the transient map is "the same wall Core's SwiftSync hits" is too broad.
That map is a limitation of our current path, not an inherent requirement of
SwiftSync. The [original SwiftSync design](https://gist.github.com/RubenSomsen/a61a37d14182ccd78760e477c78133cd)
aims to avoid the historical working set and random database lookups.

## Next experiment to pursue

Prototype **SwiftSync without assumevalid**, initially independently of a
Utreexo production integration:

1. Supply spent-coin data (value, script, creation height and coinbase flag)
   from a helper/sidecar rather than retaining all historical live coins for
   lookup. Bind those claims to locally parsed output data through the full
   aggregate protocol; hints and helper data remain untrusted.
2. Preserve every consensus check, including scripts, amounts, maturity,
   timelocks, transaction ordering and historical duplicate-output rules.
   Keep only bounded per-block/window state where needed. Ordinary-node mode
   must still finish with the exact durable usable UTXO set.
3. Specify and review the aggregate's soundness and checkpoint binding before
   using it to replace membership checks. The original design includes a
   verifier-chosen secret salt. Our current `TagAgg` plus exact-set comparison
   is not a reviewed implementation of that standalone validation protocol.
4. Compare against the current production path on matched real work with
   all script checks enabled. Include helper acquisition/decoding, peak memory,
   storage traffic, final verification and durable completion. Retain the
   ordinary fallback and existing resource guards.

The full-check SwiftSync design needs additional spent-coin/undo data and
still pays signature verification costs. A feasible helper source and its
bandwidth cost are part of the experiment, not free setup.

If this wins, evaluate Utreexo implicit deletion as a further step for compact
post-IBD state. Both directions need production integration and end-to-end
measurements before claiming a whole-IBD multiplier or a sub-hour result.

Related implementation to inspect:
[Utreexod v0.5 proofless-IBD release](https://delvingbitcoin.org/t/new-utreexo-releases/2371).
It predates the September proposal and is another reference for SwiftSync-based
IBD using spent-coin/undo data.

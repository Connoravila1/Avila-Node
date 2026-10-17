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

## Follow-up checked 2026-10-16

The October 1 assessment above is historical. The following upstream changes
were checked against GitHub's live API and pinned source, without starting IBD.
Avila's `main` still points to `f59b690bb789cf737ccc42b7a34192eb78f77978`;
being current with that branch does not mean these external changes are integrated.

- [Floresta #1115](https://github.com/getfloresta/Floresta/pull/1115) merged on
  October 15, at `b1f1431270b74a9488dd6134e5c31ecb23512b04`.
  Its documented mode remains **witnessless AssumeValid SwiftSync**. This updates
  the earlier draft status, not its verification guarantees. The
  [tracking issue](https://github.com/getfloresta/Floresta/issues/1363) still lists
  fully validated SwiftSync and bounded accumulator-worker cache usage as unfinished.
- [rustreexo v0.7.0](https://github.com/mit-dci/rustreexo/releases/tag/v0.7.0)
  shipped on October 9 with implicit deletion and proof fixes. This is an
  accumulator-library release, not an Avila full-validation integration.
- The [October 15 author update](https://github.com/getfloresta/Floresta/pull/1115#issuecomment-6181898425)
  records `hintsfile` 0.2.1 and a changed bit encoding. Old hint files can decode
  incorrectly; producer and reader formats must be matched. Avila's own `AHS1`
  format in `swiftsync.rs` is different again. Downloading upstream hints does
  not enable an equivalent path in Avila.
- There is now a concrete full-check research reference: Davidson Souza's
  [`feat/navss` source](https://github.com/Davidson-Souza/Floresta/tree/98fb2122652291007ab1475ef16e2ba84d2979d0),
  pinned at `98fb2122652291007ab1475ef16e2ba84d2979d0`.
  Its [experiment notes](https://github.com/Davidson-Souza/Floresta/blob/98fb2122652291007ab1475ef16e2ba84d2979d0/docs/swift-sync-tests.md)
  describe indexing hinted-spent outputs in a temporary database, then retrieving
  those prevouts for contextual and script validation. This is a compact local
  prevout-index design; it still has database lookup and compaction costs.
  The [October 10 run report](https://github.com/getfloresta/Floresta/issues/1363#issuecomment-6098327239)
  describes a non-AssumeValid experiment on a 32 GB system with SSD storage and
  GPU assistance. Its measurements are author reports, not Avila results or
  evidence for an 8 GB laptop with a hard drive.

The non-AssumeValid fork is not a drop-in dependency. Its pinned manifests refer
to local sibling trees (`ultra-fast-database`, `rust-bitcoinkernel-batch`, and
`ultrafast-secp256k1`), and its experiment notes explicitly describe a possible
concurrent-reclamation race, a prior OOM, and remaining measurement work. Source
availability does not establish production readiness or complete consensus coverage.
No upstream executable was built or benchmarked during this review.

### Full validation remains the acceptance requirement

`assumevalid` permits selected historical script/signature checks to be omitted.
It is an explicit operating tradeoff, and cannot demonstrate faster execution of
the same full verification workload. Bitcoin Core describes the behavior and
`-assumevalid=0` in its
[release documentation](https://github.com/bitcoin/bitcoin/blob/master/doc/release-notes/release-notes-0.14.0.md).
Avila's full-validation run must use `--assumevalid 0`; witnessless AssumeValid
results belong to a separate comparison.

SwiftSync itself need not omit signatures. The next implementation investigation
should use the full-check reference to evaluate a bounded prevout representation
and pipeline, while retaining Avila's validation engine. Any aggregate replacing
membership checks needs the protocol review already required above, including
secret salt, full coin-data binding, checkpoint binding, duplicate-output handling,
timelocks, maturity and double-spend rejection. Finish with the usable durable
UTXO set required by ordinary-node mode. Preserve the conventional fallback.

Before a whole mainnet run, validate the candidate against valid/invalid fixtures
and a reference implementation, exercise interruption and reorg handling, and
measure it under the actual memory cap. Report database and helper costs. The
existing write-deferral mode remains unsuitable as a substitute for this work.
This follow-up changes research status only; it claims no implemented Avila speedup.

### Local shadow experiment

The accompanying implementation adds isolated `swift_audit` and `swift_stump`
modules, a checkpoint shadow example, and a separate `swift_prevouts` redb
index with a `swift_prevouts_shadow` example. They are not called by node startup
or IBD. The latter replays only the committed mainnet heights 0–500 fixture with
`assume_valid=None`: ordinary full validation supplies a local final-UTXO oracle,
and the side index supplies historical input coins to the shadow audit while
canonical Chainstate remains the acceptance path. It checks exact final UTXO
equality and provisional roots against a `MemForest` oracle. This early fixture
does not cover modern witness/taproot-era blocks, establish membership or
spentness proofs, or implement stateless full-validation sync. Native validation
is pending; these source assertions are not results or performance evidence.
See the [experiment record](../experiments/2026-10-16-swift-checkpoint-shadow.md)
and [LOG 79](../experiments/LOG.md#experiment-79--swift-checkpoint-shadow-prototype)
for scope, guarded commands, evidence status, and remaining integration
requirements.

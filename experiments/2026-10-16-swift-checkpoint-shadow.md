# Experiment #79 — Swift checkpoint shadow prototype

**Status:** bounded shadow modules/examples added; local full workspace tests,
all-target Clippy, and all three bounded fixture modes passed. No benchmark,
live sync, or production integration is claimed.

## Question

Can an ordered implicit-deletion root builder reproduce the ordinary
`MemForest` roots for a small, fully validated Bitcoin history when a local
final-UTXO oracle supplies which created outputs survive a checkpoint? Can a
separate keyed multiset audit detect a deliberately altered input-coin copy?

This is a fixture correctness probe for the new shadow-only
`swift_audit` and `swift_stump` modules, not a claim that SwiftSync spentness
hints are sound enough to replace UTXO membership checks.

## Fixture and method

`crates/avila-consensus/examples/swift_checkpoint_shadow.rs` reads the committed
mainnet block fixture `mainnet-blocks-000000-000500.dat`: 501 blocks, heights
0 through 500, 114,278 bytes, SHA-256
`ef9cb1e45eaaafa55d23016d7dfce3e8f64f56609573e18b9a8940b8b1ac3d73`.
The example checks the size and digest before decoding. Its byte, block, output,
oracle-coin, and stump-buffer limits are explicit in the source.

The positive run makes two ordinary `Chainstate` replays with
`params.assume_valid = None`. The first replay supplies the final live-outpoint
set. In the second replay, each spendable output is classified against that
local set; all blocks still pass through ordinary block acceptance. A
checkpoint-bound, locally keyed audit compares the multiset of output coins
classified as spent with the coins resolved for inputs. An ordered builder
receives each block's Avila leaf commitments, using `None` for outputs the
local oracle says were spent by height 500.

For an independent root oracle, the example adds every spendable output
position to rustreexo's `MemForest`, then explicitly deletes positions absent
from the local final-live set. The resulting roots and leaf count are compared
with the provisional implicit-deletion stump.

The `--tamper-input` negative mode increments the value in one audit-owned
input-coin copy after its block has already been accepted. The expected audit
result is `Mismatch`; it does not alter the parsed block, `Chainstate`, or
oracle. In this mode the example does not finish the provisional stump from an
audit receipt.

## Current evidence and validation state

The local full workspace test suite passed with 1,124 passed, zero failed, and
five ignored tests. This included 595 consensus tests and 144 node tests. It
completed in 457 seconds with 1,942 MiB peak under the 2,560 MiB guard.
Workspace Clippy passed for all targets with `-D warnings`.

All three native fixture modes passed: the positive checkpoint shadow matched,
the `--tamper-input` mode detected the expected audit mismatch, and the
prevout-backed shadow reported audit `match`, checked height 500, 513 stored
prevouts and 55,858 encoded bytes, final UTXO equality with full Chainstate,
and provisional stump roots equal to the explicit `MemForest` oracle. The
three fixture modes completed in 28 seconds with 593 MiB peak. Modern
witness/taproot coverage remains false.

The remote `researchhead7209` run passed workspace tests and reproducibility,
but its offline `swift_prevouts_shadow` step initially failed because the
example tried to reopen redb while the original store held the exclusive lock.
This was a fixture resource-lifetime failure, not a consensus validation
failure. The example now saves bounded metadata and drops the original store
before reopening; the corrected native fixture run passes. A remote CI rerun is
still outstanding.

No IBD was started. These modules remain experimental shadow tools: they are
not wired into production chain acceptance or IBD, do not replace conventional
UTXO membership checks, and establish no speedup. The fixture remains limited
to heights 0–500 and lacks modern witness/taproot coverage.

The following guarded commands reproduce targeted unit checks and fixture modes
serially; the full workspace test and Clippy results above were also run:

```sh
tools/guard_run.sh --max 2560 --reserve 1024 -- cargo test --release --locked -p avila-consensus swift_audit::tests
tools/guard_run.sh --max 2560 --reserve 1024 -- cargo test --release --locked -p avila-consensus swift_stump::tests
tools/guard_run.sh --max 2560 --reserve 1024 -- cargo run --release --locked -p avila-consensus --example swift_checkpoint_shadow
tools/guard_run.sh --max 2560 --reserve 1024 -- cargo run --release --locked -p avila-consensus --example swift_checkpoint_shadow -- --tamper-input
tools/guard_run.sh --max 2560 --reserve 1024 -- cargo test --release --locked -p avila-consensus swift_prevouts::tests
tools/guard_run.sh --max 2560 --reserve 1024 -- cargo run --release --locked -p avila-consensus --example swift_prevouts_shadow
```

## Limits and next work

Heights 0–500 are an early 2009-era fixture and do not exercise modern Bitcoin
script and soft-fork rule coverage. The experiment has no external helper
parser or authentication protocol, no whole-chain migration, no durable UTXO
construction, no reorganization handling, and no production stateless
full-validation path. Ordinary `Chainstate` retains and validates its UTXO
state throughout both replays; the stump is shadow output only. The leaf
commitment uses Avila's existing coin leaf scheme and is not a BIP Utreexo
interoperability format.

### Follow-on bounded prevout-store probe

`crates/avila-consensus/src/swift_prevouts.rs` adds an isolated checkpoint-bound
redb index with explicit entry, encoded-byte, batch, record, script, and cache
limits. Its rows contain Avila compact full-coin records keyed by canonical
outpoint; checksums detect accidental corruption only and do not authenticate
rows or prove membership/spentness. Opening checks bounded metadata and table
length without scanning records, while lookups strictly validate framing and
decoding.

`crates/avila-consensus/examples/swift_prevouts_shadow.rs` replays the same
fixture using `assume_valid=None`. It resolves previous-block inputs from the
temporary index, resolves same-block inputs only from earlier transaction
outputs, compares indexed coins with canonical full Chainstate, and writes new
rows only after each block connects. It compares final UTXO contents and
provisional stump roots against independent full-validation and `MemForest`
oracles. The program rejects all command-line arguments and arbitrary fixture
paths. The 0–500 early-history fixture does not exercise modern
witness/taproot-era blocks. This is a storage/replay probe, not a membership
proof, IBD integration, or speed measurement.

The local unit suite, Clippy, and bounded fixture examples passed; the remote
CI workflow should be rerun to confirm the repaired example in that environment.
Next work is to measure the index against identical full-validation rules and
account for helper and storage costs. These fixture results are not a reason to
enable an implicit-deletion path for mainnet.

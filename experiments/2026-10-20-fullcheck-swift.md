# Full-check SwiftSync implementation boundary

Recorded: 2026-10-20. This is an implementation and architecture note for the
bounded SwiftSync/Utreexo work in the `ibd/swift-20261020` worktree. The source
includes an explicitly opted-in full-check path, node TCP fixtures, and
promotion into an ordinary datadir. Scoped release suites, workspace Clippy and
rustdoc, and the release CLI smoke passed on the recorded source tree. No
whole-IBD performance result is claimed.

## Implemented in this worktree

`Hints::decode_bounded` now accepts a caller-selected survivor ceiling, checks
the serialized count conversion and expected-length arithmetic before allocating
the survivor vector, and rejects over-limit files. Callers consuming an
untrusted hints file must use this bounded entry point with a limit derived from
their explicit memory and coin-count budget. The legacy `decode` entry point
remains for existing bounded local fixtures.

`SwiftLiveIndex` now stores only current live outpoints, keyed by all 36 bytes,
with 5-byte creation-height/coinbase metadata. A spend physically removes the
row; absence means missing or spent. Ordered block events commit atomically
with the tip, private audit snapshot, and provisional survivor coin updates. A
bounded undo window (default 288 heights) restores all of those records on
rewind; older reorgs require discarding the provisional index and falling back.
Live, survivor, and undo encoded bytes have separate explicit ceilings. The
redb file is created owner-only and rejected on open if group/other access is
present. This remains an exact full live-outpoint index, not a stateless index.

`SwiftValidationEngine` is a sequential full-check adapter. It validates headers,
context-free block rules and contextual rules, checks BIP30 against the exact
status index using the shared connector predicate, and resolves prior-block
claims against indexed liveness and creation metadata. Same-block inputs resolve
only from earlier transactions. It supplies current-block coins to ordinary
`connect_block` with `assume_valid=None` and scripts enabled. The full coin body
for an external claim is intentionally not looked up in an all-history coin
database: its value and script are validated during connection and bound to the
locally parsed output transcript by the keyed checkpoint audit.

For exact repeat blocks, the engine requests claims for old live coins that are
overwritten, seeds them into the ordinary connector so its undo transition can
be checked, and accounts for the overwritten incarnations separately in the
aggregate. At checkpoint finish it streams the exact live set against the
disk-backed helper-survivor table, and only marks the private stage complete
after the keyed audit matches. Helper coin payloads are accepted only for
outputs created locally and are persisted with the matching status transition.
After a matching checkpoint audit, the completed database can be reopened and
its exact full survivor UTXO streamed through `for_each_audited_survivor` for a
separate promotion transaction. The chainstate consumer now stages a
conventional redb datadir in a unique sibling directory, imports survivor rows
in bounded batches, carries over the retained full-body/full-undo window, writes
ordinary state metadata, reopens the result, and compares streamed coin count
and MuHash before publishing. It accepts only the opaque completed-audit token,
requires `assumevalid=0`, rejects a nonempty destination, and removes its stage
on failure. The fully checked pruned-history marker reaches only the retained
rollback floor; full bodies and undos remain available above that floor, and
older disconnects fail closed through the ordinary chainstate floor checks.
The promotion and engine lifecycle have targeted source fixtures, but the
combined tree still needs serialized qualification, including continuation,
prune/restart, and within-window reorg after promotion. No performance claim is
made. The completed engine retains the last 288 serialized full block
bodies and ordinary connector `BlockUndo` records in its private redb store, and
can mint an opaque in-process promotion source only after the transcript, stump,
header path, transaction metadata, and rollback-floor checks pass. The chainstate
promotion consumer stages and verifies the conventional datadir. The rollback ring and compact
Swift undo journal share a configured encoded-byte ceiling; exceeding it fails
closed to ordinary validation rather than emitting a partial promotion source.
`getchaintxstats` metadata is streamed from the in-memory validated `HeaderTree`;
a resumed process must reconstruct its connected transaction metadata before it
can mint this source.

`avila-p2p/src/swift_spent.rs` contains a bounded Draft BIP455 codec and exact
response correlator. It understands only the draft's long
`getbspent`/`bspent` commands, feature pair, CompactSize, height/coinbase code,
CompressAmount, and reconstructable scripts including P2WPKH, P2WSH, and P2TR.
It binds responses to an exact requested block and expected input-index subset,
checks the requested cutoff, and caps payload, record count, script length,
pending requests, and pending index bytes. The opt-in manager negotiates the
draft BIP434 feature, requests claims from qualified peers, and routes captured
bodies through the provisional ordered driver. It uses long command names;
BIP-324 short IDs remain unassigned in the draft and are intentionally not
invented here. Ordinary peers generally do not advertise this draft feature,
so the opt-in attempt falls back to ordinary validation when no provider is
found.

The Utreexo adapter now uses rustreexo 0.7 as a runtime dependency for the
height-ordered `Stump::modify` implicit-deletion transitions. Only outputs
still live at the end of a block receive a leaf position; a same-block
create-and-spend is omitted exactly as the ordinary Utreexo connector omits it.
For a block-end survivor, the checkpoint hint chooses a normal hash or an
implicit empty hash. It rejects empty or placeholder hashes supplied as live
leaves, persists roots, leaf count,
cursor, limits, and full checkpoint binding in the same redb block transaction
as the live index, audit state, and survivor table, and restores the prior stump
snapshot from the bounded rewind journal. The adapter remains provisional until
the full audit matches. It has differential source tests against an explicit
`MemForest` and the 0.7 API; final combined-tree qualification remains pending.

`SwiftAudit` now serializes its private secret and aggregate state. The engine
stores this snapshot atomically with each block update, provides a resume
constructor, and restores it in the same transaction as live/survivor rows on
rewind. External per-block claims have a 100,000-record cap and a 64 MiB encoded
payload budget including a per-record allowance. The protocol decoder must
enforce the same budget before allocating the claim slice; this engine API
receives already-decoded claims. Budget exhaustion is a local resource failure
and must route to ordinary validation.

The existing shadow components provide useful bounded building blocks:

- `SwiftAudit` binds coin commitments to a random per-session key, network, and
  checkpoint; it compares output records classified as spent with supplied
  input-coin records.
- `SwiftPrevoutStore` is an older bounded historical-coin experiment. It is not
  used by the new engine and must not become its all-history acceptance oracle.
- `SwiftStumpBuilder` consumes height-ordered output positions with bounded
  pending batches and only returns explicitly provisional roots.
- The `swift_prevouts_shadow` fixture runner runs `Chainstate` with
  `assume_valid=None`, compares the resulting UTXO set against a conventional
  full-validation replay, and compares provisional roots against an explicit
  `MemForest` result.

These pieces do not yet compose into a stateless or generally deployable
SwiftSync path.
In particular, the fixture labels output survivors from the conventional
oracle, checks each side-index input against `Chainstate`'s live UTXO, and uses
`Chainstate` as the acceptance engine. Its 0–500 fixture predates witness and
Taproot. The current result is therefore an early historical shadow comparison,
not a demonstration that untrusted helper data can independently drive
full-validation IBD. The standalone `swift_fullcheck_fixture` runner drives
this engine from committed raw blocks and helper-side full coins, with no
`Chainstate` acceptance oracle. A separate local TCP fixture exercises the
opt-in node caller, provider negotiation, promotion, no-provider fallback, and
a bad-helper case. It generates helper data from test fixtures, not a deployed
public service. These tests do not establish mainnet-scale helper availability
or performance; final serialized qualification remains pending.

## Functional stage boundary

The first useful integration stage is now an explicitly opted-in, bounded
full-check attempt that promotes only after its audit succeeds. The engine and
local TCP fixtures are present; final serialized compile/run review remains.
The path must
read locally parsed blocks and untrusted full spent-coin records; bind the
records to network and checkpoint; validate block and transaction order; reject
unknown, future, duplicate, and already-spent outpoints; and run every existing
contextual and script check with `assume_valid=None`. It must preserve coinbase
maturity, fee/subsidy limits, absolute and relative locks, BIP30 exceptions,
duplicate transaction handling, and same-block spends. A failed or exhausted
resource budget must reject the candidate and leave the ordinary validation
path available.

At the checkpoint, the keyed aggregate detects inconsistent helper data only
after the local transcript has established which outputs exist and which inputs
were consumed in valid order. The aggregate is not a substitute for local
ordering, double-spend, or duplicate-outpoint checks. The modern signed regtest
fixture tests engine verdicts against a conventional oracle, while the TCP node
fixture tests provider-driven acceptance and promotion; neither is a mainnet
scale availability or performance demonstration.

### Concrete reuse barrier in the current validator

`connect_block` is a useful reuse point: given a `UtxoSet` and `ConnectContext`,
it performs UTXO-dependent input checks, maturity, fees and subsidy, BIP68,
sigop accounting, script checks, and BIP30 presence scans. A caller can seed an
ephemeral set with claims for one block; outputs then become visible in normal
transaction order, so same-block spends do not require preloading future
outputs. Header validation and `check_block` plus
`contextual_check_block` remain separate caller responsibilities.

The original blocker was BIP30 visibility. Its duplicate-output scan asks only
`UtxoSet::have` for each candidate outpoint. Seeding only inputs claimed by the
current block misses unrelated live coins with a colliding outpoint. Seeding
the checkpoint survivor list can expose coins whose creation block is later
than the candidate, and it omits coins that are live at the candidate but spent
before the checkpoint. Therefore a sound caller needs a complete current-live
outpoint-presence view or an equivalent validated historical status index at
each height, with creation height and spend-order information. The current
`UtxoSet` has no pluggable membership fallback for that index; its coin lookup
and presence checks use its own layers. The engine now prechecks BIP30 against
the compact index before calling `connect_block`, and seeds only matching
repeat-block overwritten coins so the ordinary connector records them in undo.
The engine uses the shared enforcement predicate from `connect.rs` and accepts
live collisions only for the exact historical repeat blocks.

Utreexo implicit-deletion staging consumes the locally validated, ordered
output transcript and its spentness classification. Its stump remains
provisional; ordinary chainstate promotion imports the audited full survivor
UTXO and retained block/undo window, not the stump as consensus state. Durable
resume, bounded rewind, checkpoint fallback, and normal post-IBD coin lookups
are implemented in separate staging and chainstate components and still require
combined qualification.

## Architecture gaps before production use

1. **Protocol and provider deployment:** BIP455/BIP456 remain draft dependencies
   and ordinary peers do not generally serve this data. The opt-in mode needs a
   qualified, available helper/provider source and a reviewed protocol before
   broad deployment. No public helper endpoint or deployed provider was found
   for this run; local fixtures supply test data.
2. **Modern and adversarial coverage:** signed regtest cases cover witness-v0,
   Taproot, timelock and mutated-signature checks, and the node TCP fixture
   covers provider success, absent-provider fallback, and a bad claim. Broader
   boundary coverage and independent review of the complete transcript remain
   necessary before production deployment.
3. **Bounded durable lifecycle:** the live index, audit snapshot, rustreexo 0.7
   stump snapshot, and provisional survivor records now share one atomic redb
   transaction and bounded undo journal. `resume` restores both audit and stump
   state when the caller supplies a header tree rebuilt to the exact durable tip.
   Exact parameter commitments, checkpoint binding, a retained undo/body window,
   and conventional-datadir staging are present. Remaining lifecycle gates are
   crash injection across the cross-database handoff, broad prune/restart/reorg
   checks, and deep-reorg recovery characterization.
4. **End-to-end qualification and performance:** the CLI caller ties provider
   acquisition, ordered validation, bounded queues, audit, promotion, and
   ordinary fallback together. It remains opt-in and has not been qualified on
   mainnet-scale history. Complete serialized tests, run an actual deployment
   with a qualified provider, and measure full scripts, memory, helper bandwidth,
   and storage traffic before making an IBD performance claim.

Ordinary node sync remains the default; Swift requires an explicit checkpoint,
hash, hints file, workspace, and separate destination directory. It is not
enabled for the existing live datadir. This implementation is not evidence of
a whole-IBD speedup or completion of all seven requested developments.

## Local qualification on the combined source tree

The serialized local gates passed for the final Swift-source candidate:

- Workspace Clippy: `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- Workspace docs: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`.
- Release tests: consensus library 665 passed / 4 ignored; consensus fault-injection and property integration tests 28 passed; P2P library 208 passed; node library 159 passed. The node suite includes one real local TCP Swift test with qualified-provider promotion, no-provider ordinary fallback, and dishonest-helper no-promotion cases.
- `cargo check -p avila-cli --all-targets` and `cargo check -p avila-node --all-targets` passed before the final lint-only cleanup; the final workspace Clippy check compiled all workspace targets including GUI.

The block-body disk prefetcher reserves 512 MiB decoded space at its 64x
amplification bound, admitting two maximum-size serialized blocks (4,000,000
bytes each) while preserving the four-job window for smaller bodies. Its
boundary test confirms maximum-size bodies are admitted and the decoded cap
remains enforced. The recent-window A/B pair predates this cap and is not a
measurement of it.

## Post-qualification runtime status (2026-10-20)

This section supersedes the pending-CI and not-installed statements recorded
above at the earlier review point. GitHub Actions run
[39469309764](https://github.com/Connoravila1/Avila-Node/actions/runs/39469309764)
passed for published main commit `cca4b33243b35f6fa5c4639d62e675f438d46b2a`,
tree `5b8f3a7a1a0cdf3dc6ca3c67806dd3e9482bc75c`. The Linux workspace job
passed formatting, all-target Clippy, unit/integration tests, documentation,
CLI smoke, and `window_join` regressions; the reproducible release build job
passed two independent builds and hash comparison. The exact API response and
source-identity receipt are retained in the private qualification directory.

The qualified release CLI from source commit
`6713f6926bc88b7e92adb0745b606ab74f964a72` (same source tree as published
main) has SHA256
`5a724b16e585ac95d69fea07c7ee318b80539e68c8e30cb5ce3948f5e9106d4d`. It was
installed on 2026-10-20 after the gates passed; the previous CLI and its
receipt were preserved at
`~/.local/opt/avila-node/previous/qualified-cli-20261020T175518Z/`. The GUI
binary was left untouched and retains only its earlier, separate provenance.

The managed node restarted cleanly at the saved mainnet checkpoint, height
325,897, hash
`00000000000000000d92abf9d5e74567f446ae2d4889fd3eb9dba994ffa5973c`; the
restart receipt matched the installed CLI hash. At 2026-10-20 17:57:43 UTC,
the live status reported height 326,137, six peers, `assume_valid_checkpoint`
null, and historical scripts required, with full-validation coverage from
height 0 through 326,137. Ordinary IBD is active. The separate Swift helper
path remains experimental and opt-in; it is not enabled for this node. The
health trace and 14-day sampler are armed for the current process; the sampler
result is pending. The first health sample recorded 3,934,830,592 current
cgroup bytes and 3,997,360,128 peak bytes under the 4,294,967,296-byte limit,
with zero memory-max, OOM, and OOM-kill events. These are point-in-time runtime
observations, not a performance claim. Mainnet-scale helper-backed Swift IBD
and whole-IBD speedup remain unqualified.

### Final source and runtime follow-up

The exact published source `ba710e101cefc73ecdb6b89834631eda530a2869`
(tree `9a6c8470443cc5ecbaac0393cee5a1fe9c3bb52c`) passed GitHub Actions run
[39478010087](https://github.com/Connoravila1/Avila-Node/actions/runs/39478010087),
including its Linux workspace and reproducible release jobs. Its qualified CLI
SHA256 is `dc64cf2d9a684239b355c143bfdfec835423d50bba85a39a1508830081576570`;
it is installed while the previous CLI/receipt remain preserved and the GUI
binary remains unchanged. The exact CI response and source identity are private
receipts alongside the install gate record.

The node cleanly stopped at height 331,859 and the restarted process passed the
automatic restart check at that height. Both saved checkpoint hashes matched:
height 331,833 at
`00000000000000000c6da2d95bd25cc0f9d4c2e4ab28bf1437a2e6099ec601cf`, and
height 331,859 at
`000000000000000019388bf5b12b0c100d570cf53d3b309e5b7052833e13440c`. The
latest observed status at 2026-10-20 19:00:44 UTC was syncing at height 332,366,
with full-validation coverage from genesis, no AssumeValid checkpoint, and
historical scripts required; a fresh CLI RPC query succeeded at height 332,389.
A transient `waiting_for_rpc` status had cleared by then. A PID-bound health
trace and 14-day sampler for
heights 600,000–600,127 are armed; the sampler result is pending. The first
health sample recorded 3,809,837,056 current / 3,861,565,440 peak cgroup bytes
under the 4,294,967,296-byte limit, with zero memory-max, OOM, and OOM-kill
events. Ordinary IBD is active and Swift remains opt-in/off. These observations
do not establish a whole-IBD speedup. The final private runtime receipt is
`~/.local/state/avila-review/ibd-runtime-handoff-ba710e1-20261020.json`.

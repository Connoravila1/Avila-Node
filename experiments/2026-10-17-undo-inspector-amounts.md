# Historical transaction input amounts from undo — 2026-10-17

## Scope

This change is a read-only block-inspector aid. It can show the prevout values
and fee for a transaction when the matching undo data is retained. The query is
pinned to the active-chain height and block hash, and the node additionally
checks the selected transaction's index and txid against that block body. It
does not query the current UTXO set, fetch prevouts from peers, or change block
validation, script checks, or consensus acceptance. If the data cannot be
matched or safely read, the inspector reports the values as unknown.

For in-memory tail and sorted-run undo, the implementation borrows the retained
record and reads only the selected transaction's amounts. For backend records,
it streams the legacy or compact encoding through a bounded parser; it does not
construct `Coin` or `Script` objects. The compact amount path uses a local
checked decompression equivalent; it does not change the snapshot codec or its
existing wrapping behavior. It skips compressed script payloads by encoded
length and does not decompress or validate scripts. The scanner checks the
undo block-hash tag, canonical length framing, transaction/input counts,
truncation and trailing bytes, selected amount ranges, checked sums, output
totals, and the resulting fee range. A request returns at most 100 input
values; aggregate amounts are checked over all inputs for that transaction.

## Persisted-record admission and limits

Before reading a backend undo value, the implementation requires complete
current-writer admission metadata for the retained undo table and checks a
sticky maximum encoded-record size. Any missing coverage makes persisted
amounts unavailable; a recorded maximum over 8 MiB makes persisted amount
queries too large. The admission row and undo row are written and removed in
the same database transaction. The maximum does not shrink on rewind. Existing
databases are not backfilled, so their persisted undo amounts remain unknown
unless every retained undo row has admission metadata. No rewrite or backfill
happens automatically, so existing databases without complete metadata remain
unavailable for persisted amount inspection until their uncovered undo rows
are removed or explicitly rewritten. Tail and run records are not subject to
this backend-wide admission gate.

The 8 MiB limit bounds the admitted encoded record and parser work for normal
current-writer records. It is not a hard process-RSS limit: redb may load a
whole B-tree leaf page to return a value, and page layout, neighboring values,
allocator overhead, or arbitrary database corruption can affect memory use.
The node's process memory guard remains necessary. No claim is made that a
single query has a strict 8 MiB RSS ceiling.

## Validation status

The guarded native workspace gate passed in 319 seconds with a 2,560 MiB cap,
1,024 MiB reserve, and swap disabled; peak usage was 2,031 MiB. It included
1,172 Rust tests (zero failures, five ignored, including 86 GUI tests), 17
Python tests, workspace formatting, all-target Clippy with warnings denied,
rustdoc with warnings denied, CLI and GUI release builds, and CLI
`check-config`, offline-inspect, and GUI-help smoke checks. Source fingerprint:
`b8d1e8aad825943419f4e7fc25bb46e01387dd91c0d3169c8ef97a0c41458f2c`; build
revision `133f60ed12fbda2f3440e2fe005d27e2ae026a5e+dirty`.

Installed CLI SHA-256:
`9fa0079142f80ea292fc4bbd6bff213755ecf7dd31491e2ca991645a480b7d0d`. Installed
GUI SHA-256:
`b0ee9470af909e3622fdd0df7395f13aa3f54dfd62ed5f3c563a0a3d5a4aae0c`.
The native live-node inspection proof below is separate from this build and
test gate.

The first native gate stopped at compilation because `ReadableTableMetadata`
was missing from imports used for table length checks; that import was added
before the passing rerun. The tests cover legacy and compact scanners against
borrowed undo, hash/count/framing failures, truncation and trailing bytes,
money bounds, active-chain and txid/index pinning, empty input pages, checked
compact-amount overflow behavior, and backend admission behavior for complete,
incomplete, and oversized metadata histories. No speed or completed-IBD claim
is made.

## Native inspection proof

The first new process, PID 1,092,736, loaded the height-254,851 checkpoint.
The supervisor then cleanly stopped at 254,867 and automatically restarted
from the height-254,867 checkpoint; the restarted process, PID 1,093,302,
reached 254,893 at 08:20:16.210 UTC. At 08:20:39.712 UTC, the manual proof
verified that current height 255,049 remained a descendant of the saved
height-254,851 checkpoint by matching its ancestor hash. The running node
retained the same full-script policy (`assume_valid_checkpoint: null`,
`historical_scripts_required: true`), 3,072 MiB cgroup cap, swap disabled, and
`MALLOC_ARENA_MAX=2`.

At 08:20:39.754 UTC, native RPC inspection of block 255,048, transaction 1
(`404894931aa227ba644ba6ddeadc35ab69c3c8cb00f716bc4ddf2d0ea3a12fd9`) returned
one input worth 9,994,973,500 sat, outputs totaling the same amount, fee 0, and
source `block_undo`. A `u32::MAX` empty input-page query retained the aggregate
fee, and a wrong txid was rejected. A retained body at height 250,755 with
unavailable undo returned unknown amount/fee fields. This confirms the intended
unknown-state behavior for a body whose undo is not available.

The native GUI showed block 257,285 transaction 1
(`e0236df7f02f5611faa1de318c3e462477a0aa6e8939b7ab0ae30d94dd4085ea`): one
input at 7.22282802 BTC, two outputs, zero fee, 258 vB, 0.00 sat/vB, the
`block_undo` source caption, and the per-input value at both 1440×900 and
760×600 at 100%. Separately, an earlier query of block 255,048 returned amounts
over RPC, but a later GUI detail response showed them unknown. This is consistent
with incomplete persisted admission coverage, but the exact undo tier and timing
were not proven. The UI displayed that unavailable state; this is not evidence
of automatic retry.
Closing the GUI monitor exited 0 without stopping the same
daemon PID, which advanced from height 256,261 to 258,591. The GUI proof ran
under a 512 MiB cap and 512 MiB reserve, peaked at 108 MiB, and took 196 seconds.

The saved restart proof, RPC proof, and GUI proof are recorded in the local
evidence files `undo-amounts-restart-proof.json`,
`undo-amounts-native-rpc-proof.json`, and `undo-amounts-native-ui-proof.json`;
the GUI transaction came from the recorded fixture. No native positive-fee
transaction was demonstrated in this earlier proof (a later native positive-fee
sample is recorded separately). IBD remains
incomplete, and the armed 600,000–600,127 receipt-window collection has no
result yet. These checks establish bounded display behavior on the sampled
transactions, not modern-chain coverage, speedup, full IBD completion, or
accessibility qualification.

## Checkpoint provenance

The saved state used for the review was captured at 2026-10-17
08:12:04.456 UTC: height 254,851, block hash
`000000000000000b68778ca04ce8479267de0aa6aa65eb075d354671dd39aca4`, format 4,
97,116,303 bytes. The checkpoint file SHA-256 was
`f33228a4c17241a018154d359af7445ef4621a8c6b04910cde3bce9338784897`. The
preceding CLI binary had SHA-256
`adfa4d2cf3eeecd380af1094290c0464018638ba86e328b05845ff9b316c1d68`; its validation policy required historical scripts with no
AssumeValid checkpoint. This records restart provenance only and is not a
claim of completed IBD or modern-chain coverage.

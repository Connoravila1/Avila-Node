# Storage layout and recovery

This page separates the current storage layout from an older design comparison
that predates disk-backed coins and persisted undo.

## Current layout

| State | Storage | Access and recovery |
| --- | --- | --- |
| Profile scope | Ordinary disk-backed redb mode | This table describes this profile. In-memory/test profiles can retain undo in memory instead. |
| Block bodies | Append-only `blk*.dat` files | Sequential sync writes and indexed reads; pruning removes old whole files. |
| Header index and chain snapshot | Versioned `state.dat` snapshot | Rewritten atomically on checkpoint; v4 externalizes coins and retains chain/header/bookkeeping state. |
| Coins | redb `COINS` table behind `UtxoSet` | Dirty and flushing overlays, optional overlay base, and persistent backend. Updates flush in backend transactions. `-dbcache` is not a total-process memory limit. |
| Undo | redb `UNDO` table with height/hash association | Written with coins and tip metadata; used for disconnect/recovery and reorg handling. It is no longer stored inline in `state.dat`. |
| Undo inspection admission and retention floor | Small redb metadata tables | Display admission is separate from consensus undo reads. The optional persisted GC floor is height-and-active-hash bound and changes recovery requirements. |
| Other indexes | Their feature-specific files/tables | Independent of the coin/undo checkpoint path. |

Recovery can reconcile multiple committed backend blocks ahead of the saved
snapshot using their persisted undos, then replay bodies after the snapshot.
It is not limited to a single commit ahead. When an undo-retention floor is
present, recovery must honor it: snapshots below it or with a mismatched
active-chain anchor fail closed, as do recovery fallbacks that would cross it.
The floor protects only databases written with the new metadata and binaries
that enforce it; rolling back to an older binary is not safe. Backups should
pair `state.dat` with the matching coins database rather than treating either
file as a standalone checkpoint.

Ordinary redb pruning advances the hash-bound undo floor only after a current
checkpoint and successful block-body pruning. It removes at most 256 UNDO and
matching admission keys per prune call. This is a key-count batch, not a hard
encoded-byte, physical-page, total-retention, or RSS bound. Remaining rows at
or below an advanced floor can be collected in later calls. Logical row
deletion does not compact redb or shrink the database file. This GC path is
skipped for sorted runs, flat storage, AssumeUTXO, and the redb shadow backend;
those modes are not qualified by the current experiment. See the
[bounded undo-retention experiment](../experiments/2026-10-17-bounded-undo-retention.md)
for the passed native gate, saved-checkpoint restart proof, and read-only before/after undo-GC observations. The measured database file size remained unchanged. A manual post-GC restart proof matched the saved checkpoint and persisted floor hash anchor; see the experiment for its scope and caveats.

## Historical candidate comparison

The following comparison describes an earlier in-memory design and candidate
options; it is not a description of the current architecture or a measured
performance comparison.

| Candidate | Shape | Trade-offs considered |
| --- | --- | --- |
| Earlier Avila design | In-memory coin and undo state with whole-state snapshots | Simple access model, but snapshot size grows with state. This design has since been replaced by the current redb-backed coins and undo layout above. |
| LevelDB-style coins view | Disk-backed key/value store with a cache | A possible storage design; no amplification or throughput number is asserted here. |
| Utreexo-style proof-carrying state | Compact accumulator state plus proofs | Requires peer/protocol and validation changes; it remains outside the deployed storage design. |

Historical implementation details and unmeasured candidate estimates should
not be used to infer current memory behavior, write amplification, or sync
throughput.

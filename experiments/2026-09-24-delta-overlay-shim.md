# Delta overlay — snapshot as UtxoSet's lowest layer (read shim)

**Date:** 2026-09-24 · **Status:** PARTIAL ADOPT — read path done + tested;
activation integration is the next step

## Hypothesis

An immutable SnapshotRun can serve as the UTXO set's base layer under the
existing write-back delta: reads fall through map → sim-base → backend →
snapshot; spends shadow the base with tombstones. This is the path to
"usable without materializing" — activation becomes attach, not import.

## What was built

- `UtxoSet.snapshot: Option<Arc<SnapshotRun>>` — fourth (lowest) layer.
  `get`/`have`/`lower_get`/`lower_live`/`len` all probe it in order;
  writes never touch it (spends leave tombstones in `map` — same
  shadowing semantics as the backend layer).
- `attach_snapshot` / `attach_shared_snapshot` — mirrors the backend
  attachment pattern.
- `SnapshotRun::index(path, stride)` — the sequential portable indexer:
  scans a Core-format snapshot file, builds the group-start sparse index.
  This is the no-bundle fallback that the advice invariants require
  ("anyone holding the public data can generate the artifacts").

## Two real bugs the test caught in `SnapshotRun::get`

The overlay's miss-heavy lookup pattern exposed latent bugs:

1. **EOF window clamp** — `read_exact_at` of a fixed 128KB window fails
   on the last group of *any* snapshot (window runs past EOF). Now
   clamps to `file_len - off`.
2. **Zero-count group underflow** — a miss past the last sparse entry
   walked into the zero-filled buffer tail, parsed count=0 "groups",
   and `group_left -= 1` underflowed (panic in debug, wrap in release).
   Now bounds every read to the actual bytes read and rejects
   zero-count groups.

Both are exactly the path an overlay exercises constantly: most
spend-lookups MISS the snapshot (coins spent since the base live in
the delta).

## Test

`snapshot_run_is_lowest_overlay_layer` — builds a real snapshot file
via `write_snapshot`, indexes it, attaches: resolves both coins,
spend → tombstone (`have`/`get`/`len` correct), recreate shadows,
absent coin misses cleanly. All 480 lib tests pass.

## Update — activation path landed (same day)

`activate_snapshot_overlay` is in: `check_snapshot_activation` +
`commit_activated_snapshot` helpers share the guard/commit logic, the
file streams once through `coinstats::compute_streaming` (file order IS
the committed hash order — sorted-compute verified), `SnapshotRun::index`
builds the sparse index, the run attaches as the lowest layer.
`loadtxoutset` calls the overlay path.

Verified: the same fixture file lands identical state through both
paths — every snapshot coin resolves through the file, mutable-layer
writes shadow correctly.

Remaining honest boundary: **restart persistence** — the attached run
must re-open on resume (path recorded in `state.dat`?). And a real
170M-file validation still needs a real snapshot (no Core-format
mainnet dump on disk).

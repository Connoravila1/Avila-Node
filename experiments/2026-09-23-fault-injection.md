# Experiment: crash fault-injection on the hash engine

**Date:** 2026-09-23 · **Status:** two findings, both fixed
**Artifacts:** `tests/fault_inject.rs` (file-level tear harness),
record integrity tag (hashstore format v2), tip watermark in the
index header.

## Method

Simulated torn writes at each phase of the hash commit order —
`commit_coins` (log bytes → index slots → header) → `sync` →
redb bookkeeping tx — by manipulating `coins.dat`/`coins.idx`/
`coinsdb.redb` between commits, reopening, and classifying:
recover-exact / fail-safe wedge / silent corruption.

## Findings and fixes

**F1 — torn records were silently corrupt (FIXED).**
`decode_coin_compact` validated nothing: a mid-record tear decoded
to a wrong-but-valid coin (3/16 corrupted in the probe). Fix: every
stored record now carries a 4-byte tag — SipHash-1-3 over
`key || record` with the database seeds. The key binds the record to
its slot (a torn slot repointing at another key's record also
mismatches); `get`/`iter_coins` verify before decode, so tears
become detectable misses. Post-fix: **0 corrupted** across all tear
classes.

**F2 — coins-ahead-of-tip was undetectable (FIXED → detected).**
The commit order lands hash coins before the redb undo+meta tx; a
crash between them leaves `tip_height()` at H−1 while coins are at
H — `reconcile_backend` only handles the opposite direction, and the
next connect wedged on `MissingInput` with no diagnosis. Fix: the
connecting height is written into the index header (`[48..56]`)
during `commit_coins`, before the meta tx; `open` compares and
errors loudly (`"torn commit, resync or restore required"`).

## Verified fail-safe classes

- `coins.dat` tail truncate → missing coins (wedge, detectable)
- torn slot write → missing coins + bounded probe-chain loss
- partial tail record → missing coin

All three surface as absent reads or explicit errors — never wrong
values.

## Honest caveats

- `compact()` — **closed in the same session**: both files of the
  pair now carry a generation stamp (dat `[12..20]`, idx `[56..64]`);
  the swap renames `.new` files stamped `gen+1`, and open completes
  whichever rename the crash lost from the surviving `.new`. The one
  remaining unhealable case — gen mismatch with no `.new` — errors
  loudly instead of misreading.
- File-level simulation, not process-level kills at phase
  boundaries — the same tear windows, but a real `kill -9` harness
  would be a stronger proof.
- Tag costs +4 B/record (~4% on typical 26–40 B records) and one
  SipHash-1-3 per committed coin; ingest at 500k measures ~245k/s,
  inside noise of the pre-tag baseline.
- `coins.idx`/`coins.dat` format bumped to v2 — old hash datadirs
  won't open (engine is opt-in; documented).

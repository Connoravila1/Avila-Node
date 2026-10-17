# Read-only coins database storage measurement — 2026-10-17

## Method and bounds

A small standalone utility opened a closed `coinsdb.redb` with redb 4.3.0's
read-only API and a configured 32 MiB cache. It read redb table counts and
`Table.stats()` for `coins`, `undo`, `undo_amount_admission`, and `meta`; it
did not iterate or decode records, create a writer, repair, compact, or mutate
the database. Table statistics may traverse tree pages. `stored_bytes` is
logical inserted key/value bytes and excludes index overhead. Table
`fragmented_bytes` is redb's table metric, not a measure of physical filesystem
fragmentation. Whole-database page statistics are reported as unavailable
because the pinned read-only API does not expose them; no writer was opened to
obtain them.

The isolated helper source SHA-256 was
`3be241b9fac6ff24e533254181619c380b37e0bb691b924a221730fc15b54f81`; its
standalone binary SHA-256 was
`2a50df30511a0024fc61097045a71c9a79d314686204328f6833fdfe60c8d53f`. This
utility source is not part of the main repository or shipped binaries. To
reproduce, build the local utility against pinned redb 4.3.0, then run its
binary only against a closed database under the resource guard:

```sh
tools/guard_run.sh --max 512 --reserve 512 -- <coinsdb_storage_stats> --db <closed-coinsdb.redb>
```

The short standalone build used a 512 MiB cap / 512 MiB reserve. The closed-DB
read took 19 seconds under the same cap and reserve; the guard sampled 511 MiB
peak including file cache. This is one bounded observation, not a general
memory requirement or a projection for other databases. File identity, size,
and modification time were unchanged before and after; no full-file hash was
computed.

An initial direct compile tried `ReadTransaction::stats()`, which is not
available in redb 4.3.0. The isolated utility was corrected to leave whole-DB
page statistics null rather than opening a writer. Its later standalone
smokes returned exit 0 for `--help` and exit 1 for two invalid/missing `--db`
invocations; they did not access or create a database.

## Observation

At the saved height 269,677 checkpoint, the database file was 3,944,288,256
bytes. The table statistics were:

| Table | Entries | Stored bytes | Metadata bytes | Fragmented bytes |
|---|---:|---:|---:|---:|
| `coins` | 7,439,043 | 463,874,790 | 73,748,250 | 487,753,216 |
| `undo` | 269,677 | 1,651,199,431 | 5,304,984 | 734,752,673 |
| `undo_amount_admission` | 14,826 | 652,344 | 5,188 | 10,116 |
| `meta` | 5 | 68 | 44 | 3,984 |

The undo table's logical stored bytes and the whole file size are distinct
measures; the reading does not establish how much physical file space undo
cleanup could reclaim. Admission rows cover only a subset of retained undo
rows, so persisted historical input amounts remain unavailable where the
admission gate lacks complete coverage. There was no migration, cleanup,
compaction, per-record size estimate, or undo-GC implementation in this
measurement.

After measurement, the existing v4 checkpoint at 269,677 restarted and checked
height 273,569 with the saved ancestor hash matching
(`00000000000000016ca6fc96b11da8528b7807eb1ca98163acc20c621681b087`). The
runtime still used full historical script validation
(`assume_valid_checkpoint: null`, `historical_scripts_required: true`). IBD
remains incomplete. This establishes saved-ancestor and runtime continuity
after the read-only measurement; the before/after inode, length, and mtime
checks do not prove byte-for-byte nonmutation. It is not a new storage-writer
validation or an undo-retention policy proof.

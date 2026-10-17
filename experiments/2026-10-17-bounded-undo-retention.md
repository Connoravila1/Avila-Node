# Bounded undo retention — 2026-10-17

## Scope

This change adds incremental deletion of old persisted undo rows for the
ordinary redb backend. It is intended to bound growth of the logical UNDO
table during a long initial sync. It does not change transaction validation,
the undo record format, or the existing read APIs. It does not apply to sorted
runs, flat storage, AssumeUTXO, or the redb shadow backend.

Before deleting any rows, pruning first writes and joins the ordinary current
active-chain checkpoint, then deletes over-budget block files. The undo floor
is advanced only after that checkpoint and body-prune step succeed. The floor
is persisted with the active-chain block hash at that height. When a floor is
present, startup snapshot/recovery checks fail closed if the snapshot is
missing, below the floor, anchored to a different hash, or reconciliation
fails. Backend restore checks the canonical stored hash prefix against that
active branch; restore fallbacks do not bypass a saved floor. This protects a
database with a persisted floor. The pre-existing recovery behavior for a
legacy database with no floor is not changed by this branch-binding check.
Invalidation rejects targets below the floor before changing flags, then
preflights required bodies and undos before rewind. This is not a claim that
every possible error in invalidation is transactional or error-atomic.

Collection removes at most 256 UNDO keys per prune call and removes a matching
amount-admission row in the same write transaction when one exists. A bounded
batch can advance the floor while older rows at or below it remain, so cleanup
debt may persist across calls. Under-budget prune calls checkpoint only when
there is pending GC work. The policy retains a minimum 288-block undo window;
that is an undo-retention rule, not a guarantee that old block bodies remain
available or that arbitrary deep reorgs can be recovered without redownload.
Logical row removal does not compact redb, shrink its file, or guarantee an RSS
reduction. There is no hard byte/RSS bound, and a large backlog may take hours
to drain.

The 256 limit counts keys, not encoded bytes or physical redb pages. It is not
a hard allocation or memory bound. In particular, redb page co-residency and
power-of-two page rounding can make ordinary intact pages exceed the per-record
8 MiB display/parser admission budget. Source guards restrict collection to
ordinary redb mode; runtime qualification, if completed, applies only to that
mode. It does not repair missing legacy admission metadata. Existing undo APIs
and recovery paths remain in place, with floor checks added to prevent fallback
from crossing a committed prune boundary.

## Validation status

The source adds 12 focused tests and updates the existing floor-present,
crash-ahead recovery test. They cover bounded batches, checkpoint ordering,
floor/hash binding, startup refusal for missing or mismatched state, and
recovery fallback behavior. Source guards exclude sorted runs, flat storage,
AssumeUTXO, and the redb shadow backend; no test or runtime qualification for
those modes is claimed. Three initial native-gate attempts stopped at compile
errors: an undefined test hash helper; borrowed metadata-table handling and an
invalid floor-zero fixture; and overflowing `u8` fixture tags. A fourth
attempt correctly caught a fixture that had not actually pruned its marker;
that fixture was repaired. No binary from those stopped attempts was installed.
Attempt five passed: 628 debug consensus tests (four ignored), 1,189 release
workspace tests (five ignored, including 86 GUI tests), and 17 Python tests,
with formatting, all-target/devtools Clippy, rustdoc, release builds, and smokes
passing. The guard used a 2,560 MiB cap and 1,024 MiB reserve, with 2,090 MiB
peak over 345 seconds. Source fingerprint SHA-256 was
`2007ef695d70273d2aa9723e7d82871065a386b9c00a739a00e708888b1ce96c`; the build
was from `fc95eda` plus the reviewed working-tree changes. CLI SHA-256
`430a0e63557926efea9b7aabdaa705ceb25e8f088c872cd3378f5e03fdc9f1ce` and GUI
SHA-256 `2d36a706dfbb69fcf1e7975d76b4d91e510bbdb646464fdfff3d3b5b4d42af9c`
were installed at 09:34:47.865285 UTC. At gate completion, runtime continuity
and post-GC measurements were still pending; the following sections record the
subsequent restart proofs and before/after observations. Mainnet IBD remains
incomplete.

## Pre-change database observation

A read-only redb table-statistics utility examined the closed database after a
clean stop at saved height 278,536. The v4 checkpoint hash was
`0000000000000000c7d117a7ae597543f211bc72defb038a6542ee0c58f77db2`; its
98,918,215-byte file had a verified framed checksum. The measured database
file was 6,442,684,416 bytes. Table statistics reported 278,536 UNDO rows with
1,878,483,659 logical stored bytes, 8,123,178 coin rows with 507,014,413
logical stored bytes, and 23,685 undo-admission rows. The metadata tip was
278,536, the undo floor was absent, and the UNDO key bounds were 1 through
278,536. Logical table bytes are not database-file size or an estimate of
reclaimable physical bytes.

The read-only measurement ran for 22 seconds with a 512 MiB cap and 512 MiB
reserve; the guard sampled a 511 MiB peak, including file cache. Database
inode, size, and mtime were unchanged before and after; no full-file hash was
taken, so this is not a byte-for-byte nonmutation proof. The isolated helper
used a 32 MiB redb cache and did not iterate or decode records, compact, or
write the database. Its source SHA-256 was
`a4e1ba76c4c9d8cc52c09f5c03f8bb7b07be1eaecea487a6ac9335245d8f7cfb`; compiled
binary SHA-256 was
`bf6d94331078155751ca45fab53201b704d1ddb7c8df260d34046b63331e3040`. An
initial compile caught an explicit-lifetime issue in this isolated utility;
the correction was made there only. Its command-line negative checks passed.

The installed CLI passed automatic restart verification at 09:35:44.787733
UTC at height 278,536. Manual continuity proof at 09:36:06.236955 UTC checked
height 278,621 on new PID 1,318,056 and matched the saved height-278,536 hash.
The exact installed CLI, full-validation policy, 3,072 MiB cap, swap disabled,
and arena limit 2 were verified. A later fresh observation at 09:44:29.321384
UTC showed the same PID at checked height 282,769 and blockchain height 282,761;
no hash query was made at that later height.

After a subsequent clean CLI exit (code 0), a v4 checkpoint was captured at
height 283,070 with hash
`0000000000000001249a0fadc7917a93cb93f4cfbb77ff9377aaf1fcee8782ad`; its
99,261,719-byte file passed the framed checksum and has SHA-256
`20d2802be9160b9b38a80810b6d368fbd8bcebd10cc8c3eb9e301952c9127b0a`. A
closed-database read-only measurement ran for 25 seconds under a 512 MiB
cap/reserve; sampled peak was 511 MiB including file cache. The database file
remained 6,442,684,416 bytes with matching inode/size/mtime during the read; no
full-file hash was taken. The persisted undo floor was 225,832 with raw anchor
`15eb39866d579c8ee33eeb9b8077a5e8b9efec862bb34c83e902000000000000`. UNDO
keys now ranged from 2,817 through 283,070, with 280,254 rows and
1,981,653,458 logical stored bytes. Relative to the pre-GC tip 278,536 and
278,536 rows, the tip advanced by 4,534 while the row count advanced by 1,718;
the first key moving from 1 to 2,817 is consistent with 2,816 old prefix rows
collected (11 batches of 256). Logical stored bytes grew by 103,169,799 bytes,
so this does not show a total-table-size reduction. Admission rows rose from
23,685 to 28,219, exactly the tip-height increase; no older admission-row
collection is observed in this sample. The physical database file did not
shrink. The local stop wrapper initially reported failure despite CLI exit 0;
process absence and inactive service were verified before the read-only
measurement. This was an operator-helper issue, not a Rust change, and the
repaired stop verifier has not yet been qualified by another stop.

The post-measurement restart proof passed at 09:50:11.929745 UTC on new PID
1,358,692. RPC `getblockhash` matched the saved height-283,070 checkpoint and
also matched the persisted floor at 225,832: active-chain hash
`00000000000002e9834cb32b86ecefb9e8a577809beb3ee38e9c576d8639eb15`, matching
the recorded raw anchor after byte-order conversion. Checked height was
283,195. The exact CLI, full-validation policy with historical scripts
required, 3,072 MiB cap, swap disabled, and arena limit 2 were verified. This
is a manual RPC continuity proof; the supervisor restart-check field still
referred to the earlier restart, so no second automatic-check result is
claimed. The local stop verifier has not yet been qualified by another stop.
Mainnet IBD remains incomplete. No RSS reduction, physical file shrink,
reorg-availability, or speed claim is made.

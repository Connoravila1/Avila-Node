# Prune checkpoint boundary — 2026-10-17

## Observed failure mode

The byte-budget pruner previously protected the earliest block file containing
any body above `state_tip_persisted`, because recovery might have to disconnect
the coins backend back to that snapshot. A parked future body or out-of-order
side-branch body in an old file could therefore pin the floor even when the
active chain had advanced; a measured store reached 11,800,471,692 bytes
against an 8,589,934,592-byte target. This was retention-floor behavior, not a
consensus-validation failure.

The pre-change capture was taken at 2026-10-17 08:33:44.685 UTC after a clean
exit of CLI SHA-256
`9fa0079142f80ea292fc4bbd6bff213755ecf7dd31491e2ca991645a480b7d0d`. It was
height 264,970, hash
`000000000000000e30b8a6d01a31b62ae1348c98b01eb68c664b27340419d7e5`, format 4,
97,886,099 bytes; checkpoint file SHA-256
`fb8fd543b03764bcffde5575d344a1c9f78f1f05be1aa42fff172cf78d0814d8`. There
were 88 block files, numbered 0 through 87, totaling 11,800,471,692 bytes.

## Change and recovery boundary

The prune path first checks whether the current block-file total exceeds the
configured byte budget. If it is within budget, pruning returns without writing
a chainstate checkpoint. When over budget, it checkpoints before deleting:
the chainstate drains pending script checks, flushes the dirty coins and undo
records, joins the backend commit, and writes the state snapshot at the current
active tip. Only after these operations succeed does the store delete oldest
files, preserving the append-tail file. A failure before deletion leaves the
block files in place.

After that checkpoint, crash recovery has the exact active-tip state and does
not need to rewind an ahead-of-snapshot coins backend through bodies being
deleted. Parked future bodies can be pruned; their headers remain indexed and
their missing bodies are eligible for refetch. The block store now replaces a
same-session index position when a pruned body is received again, rather than
mistaking the stale position for a retained body. Tests cover parked height 8
over active height 4, same-session refetch, and restart-before-refetch followed
by successful resubmission. The validation and script-check paths are
unchanged.

Pruning still limits reorg capability: if a reorganization needs a body that
was pruned, the node cannot activate that branch until the required body is
available again. This change does not promise automatic recovery of every deep
reorg. The block file handle is flushed before sizing/checkpointing, but that
flush is not `sync_all`; the state/coins checkpoint ordering does not imply
that every block-file byte is durable across sudden power loss.

## Validation status

The guarded native gate passed in 369 seconds at a 2,560 MiB cap, 1,024 MiB
reserve, and swap disabled; peak usage was 2,253 MiB. The debug consensus run
passed 616 tests with zero failures and four ignored in 22.01 seconds. The
release workspace run passed 1,177 tests with zero failures and five ignored,
including 86 GUI tests; 17 Python tests passed. Workspace formatting,
all-target Clippy including GUI devtools with warnings denied, rustdoc with
warnings denied, CLI and GUI release builds, and `check-config`, offline
inspection, and GUI-help smokes all passed.

Source fingerprint:
`c3b2163220691a6780c150104ee8921662536ccf6b0ba4ec1827f3349f5364fc`; build
revision `76f10a7+dirty`. Installed at 08:41:30.650 UTC: CLI SHA-256
`fc47aa59ac3e2a6b8abc5d1cd329265553d914e316f9ab2869ee1f354df5593f`; GUI
SHA-256 `e3284d48ffe088670d278b6aae1641bb9dde2291fce104a7623ad486deee24b6`.

A prior Linux CI run passed reproducibility but failed the newly added
side-branch fixture assertion because two layers at the same height 102
violated the strict ascending-tip order. The fixture now drops the wrong run
before attaching the correct one; the passing local debug and release gates
include the fixed test.

## Native mainnet prune and restart proof

At 08:42:55.604 UTC, the supervisor automatically restarted the node from
height 264,970 at the same height. At 08:43:47.719 UTC, the restarted process
(PID 1,183,864) was checked at height 265,336, and the height-264,970 ancestor
hash matched the saved checkpoint. The node used the new CLI binary
`fc47aa59ac3e2a6b8abc5d1cd329265553d914e316f9ab2869ee1f354df5593f`, with
`assume_valid_checkpoint: null`, `historical_scripts_required: true`, a
3,072 MiB memory cap, swap disabled, and `MALLOC_ARENA_MAX=2`.

Before pruning, the store had 88 files (0–87), totaling 11,800,471,692 bytes
against the 8,589,934,592-byte target. After the prune tick, it had 65 files
(24–88), totaling 8,628,801,147 bytes. The remaining 38,866,555-byte excess
is within this observation check's 128 MiB tolerance; this is not a configured
or guaranteed pruning bound. There is no hard 8 GiB + 128 MiB bound between
prune passes: the 60-second cadence can allow more than one whole file to
accumulate at high throughput. This budget applies only to `blk*.dat` files;
it does not cap the coins/undo redb files or total datadir size. Historical
undo retention in redb is not bounded by this block-file budget; no size
forecast is available.
Native `getblockchaininfo` reported `pruned: true`. Block 2,000 remained in the
active-chain header metadata but its body was unavailable, with no transactions
returned. The saved ancestor hash and full-script validation policy remained
intact after restart.

This native run did not force a live future-body refetch; the bounded fixture
tests cover same-session and restart-before-refetch resubmission. It does not
establish power-loss durability for block-file bytes, deep-reorg recovery,
speedup, modern-chain coverage, GUI behavior, or completed IBD. At capture the
node remained in IBD. The 600,000–600,127 receipt collector was rearmed for the
new PID but has no result yet; the health trace is bounded to 128 MiB.

At 08:45:18.558 UTC, the same daemon PID 1,183,864 had advanced to checked
height 265,866, and the block-file store had 64 files (25–88) totaling
8,578,585,794 bytes, below the 8,589,934,592-byte target. The earlier 08:43
sample had 65 files (24–88) and exceeded target by 38,866,555 bytes, within
the proof's 128 MiB observation tolerance. That tolerance is not a hard cap
between 60-second prune passes; at high throughput, more than one whole file
may accumulate between observations. These two finite samples show the
observed whole-file and cadence behavior, and that periodic pruning continued
while IBD was active, not only during shutdown.

A separate native GUI attach/close smoke at 760×600 and 100% displayed height
265,662 with full-script policy visible. Closing the monitor exited 0 with
zero GUI windows and left the same node PID running; it was still at 265,866.
The GUI smoke ran under a 512 MiB cap and 512 MiB reserve, peaked at 88 MiB,
and took 32 seconds. It only covers attach and close; the earlier fee display
proof is separate. No fee visual rerun, new block-map claim, accessibility
qualification, or GUI source change is claimed.

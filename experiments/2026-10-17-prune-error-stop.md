# Stop sync when periodic pruning fails — 2026-10-17

## Failure path and change

Periodic pruning can checkpoint chainstate before deleting over-budget block
files. That checkpoint flushes dirty coins and undo records through the
asynchronous coins backend and joins the worker before the prune continues. A
flush or join error can occur after the dirty map has been moved into the
worker; on failure the pending layer can be dropped while its in-flight marker
remains. The old periodic sync handler caught the prune error, logged it, and
continued the main sync loop. Continuing after that failed checkpoint could
advance validation while the persistent coins backend and active chainstate
no longer have a successful checkpoint handoff.

The periodic handler in `crates/avila-node/src/sync.rs` now propagates the
prune error as `SyncError::Store`, stopping sync through the same fail-stop
path used for other storage errors. It no longer logs and continues. This is
an error-propagation change; it does not change consensus checks, checkpoint
ordering, pruning policy, or the GUI. The adjacent comment now describes
whole-file overshoot as dependent on file sizes and incoming throughput rather
than promising a fixed `keep + one file` bound.

No live prune/checkpoint failure was injected, and this change does not claim
that the failed worker can be repaired or that sync can safely resume in the
same process. The native gate passed: 616 debug consensus tests (four ignored),
1,177 release workspace tests (five ignored, including 86 GUI tests), and 17
Python tests passed. Formatting, workspace all-target/devtools Clippy with
warnings denied, rustdoc with warnings denied, release builds, and CLI/GUI
smokes passed. Guarded validation used a 2,560 MiB cap, 1,024 MiB reserve, and
swap disabled; it peaked at 2,098 MiB over 351 seconds.

The build used source revision `c2a816e` with source fingerprint
`2f02900cadadaea5a63914daaa62cf688f10e68d1c84fa55d582cb2469b5719a`. It was
installed at 2026-10-17T09:10:43.958662Z with CLI SHA-256
`d3a0ce8bebcd8f923cb073679455cb4c9c56cf037b14455409209730db9bae3a` and GUI
SHA-256 `c1fe7ac9300623aae9d1aae7d93588072ed9b5408b4ab5eeb5fe5916d54da16e`.
The supervisor restart check passed at 2026-10-17T09:11:45.611120Z, and the
manual ancestor check passed at 09:11:53.168564Z. New PID 1,263,449 resumed at
saved height 273,718; the saved hash
`0000000000000002217fd35c22ed7cdd509e5c304ac376fe3cf37d3a9009ec4f` matched.
The running binary matched the new CLI SHA; the full-script policy, 3,072 MiB
cap, swap disabled, and arena limit 2 were verified. At the proof, the node
had resumed the saved height. A fresh status observation at
09:12:07.058162Z showed the same PID syncing at height 273,803, with no
AssumeValid checkpoint and historical scripts required. No hash query was made
at 273,803. No live prune/checkpoint failure was injected.

Before the update, a clean old-binary stop captured a v4 checkpoint at height
273,718, hash
`0000000000000002217fd35c22ed7cdd509e5c304ac376fe3cf37d3a9009ec4f`,
98,550,199 bytes, with framed checksum verified. This is a continuity
checkpoint for the build; the checkpoint file SHA-256 is
`e929b9c39c22541ca2e15746c85abf048443a285f2b856454b8e529cdbadd124`. It is
the ancestor used in the successful restart check above. Mainnet IBD remains
incomplete.

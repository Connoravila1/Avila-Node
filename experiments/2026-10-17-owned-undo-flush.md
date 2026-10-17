# Owned undo handoff probe

**Status:** the owned flush path and its bounded synthetic comparison passed
the native validation gate. This changes only how the pending undo vector is
handed to the asynchronous worker; consensus validation and persistence format
are unchanged.

`UtxoSet::flush_to_backend` remains the borrowed compatibility API. It joins a
previous worker before cloning the next borrowed undo slice, preserving the
old flush ordering. `flush_to_backend_owned` accepts the `Vec` directly, so
`Chainstate::flush_coins_with` can move its pending vector to the worker rather
than deep-cloning it again. The original `Chainstate::undos` remains available
until the join drains its committed prefix, preserving reorg/disconnect lookup
while the flush is in flight. Both paths commit coins, undo records, and tip
atomically; the owned API also feeds the existing sorted-run path.

The comparison uses `undo_flush_probe` with a fixed synthetic fixture: 64 undo
records × 32 transactions × 32 spent coins, totaling 65,536 coins with 1,024
byte scripts (67,108,864 script bytes), plus eight deterministic seed coins.
Each mode checks tip 64, all undo heights/hashes/bodies, and all seed coins
after the flush join and again after closing and reopening the backend. The
borrowed mode drops its local pending vector immediately after handoff, as
`flush_coins_with` does; the original undo vector stays retained in both modes.
This is a storage ownership probe, not a consensus fixture or a full IBD/RSS
measurement.

Build separately from the capped runs, then invoke each mode in its own process
with a distinct fresh destination. `AVILA_COINS_CACHE_MB` is set by the shell
for the child process; the example itself does not change the environment.

```sh
tools/guard_run.sh --max 2560 --reserve 1024 -- cargo build --release --locked -p avila-consensus --example undo_flush_probe
AVILA_COINS_CACHE_MB=32 tools/guard_run.sh --max 1024 --reserve 1024 -- target/release/examples/undo_flush_probe <fresh-borrowed-directory> borrowed
AVILA_COINS_CACHE_MB=32 tools/guard_run.sh --max 1024 --reserve 1024 -- target/release/examples/undo_flush_probe <fresh-owned-directory> owned
```

The borrowed run took 1,793 ms and reported process `VmHWM` of 228,828 KiB
(about 223.46 MiB); the outer cgroup sampled 351 MiB and 3 seconds. The owned
run took 1,877 ms and reported `VmHWM` of 159,464 KiB (about 155.73 MiB); the
cgroup sampled 283 MiB and 2 seconds. `VmHWM` is process resident-set
high-water; cgroup memory also includes file cache. The cgroup CPU sample was
0.00 for both and is not useful at this sampling duration. These were single
trials with potentially different cache state and clocks, so they support no
speed claim and do not establish a production-wide RSS or IBD result.

The full native gate passed in 333 seconds at a 2,560 MiB cap / 1,024 MiB
reserve, with 1,663 MiB peak: 1,158 Rust tests passed, five were ignored, zero
failed; 14 Python tests passed; workspace all-target Clippy with GUI/devtools
features and warnings denied, rustdoc with warnings denied, release CLI/GUI/
example builds, and CLI/GUI smoke checks passed. The source fingerprint was
`e7089d9bda914e3e707497c711c94405c25b6f340f0e10f272ce31de08ae3ccd`. The same
gate covered cache-occupancy telemetry based on three relaxed loads (entries,
capacity, and key bytes), which is not a full heap measurement, plus isolated
tests for thread-local cache replacement, clear, and drop behavior.

The mainnet database was cleanly stopped with persisted height 200,176 and
hash `00000000000003c91b94427e9605a6d2c21c688f33e443258c02310827ca2a88`.
An older status observation showed 199,887, so it is not the persisted
checkpoint height. The new CLI and GUI were installed and the
service resumed at 06:42Z. Their SHA-256 values are CLI
`adfa4d2cf3eeecd380af1094290c0464018638ba86e328b05845ff9b316c1d68` and GUI
`261f631d312fb1eb5435be066faab9361a5f5a5ce0839f44e1efc44946063c3e`.

At 2026-10-17T06:42:32.104174Z the installed CLI passed a clean restart,
resuming at saved height 200,176 with the same checkpoint hash. A later
real-peer CLI observation showed height 200,383, 971,821 headers, and six
connections. The validation report still had `assume_valid_checkpoint: null`
and `historical_scripts_required: true`. The attached GUI at 760×600 showed
height 200,275; closing its node window exited 0 while node PID 647865
continued to 200,383. That GUI run used a 512 MiB cap / 512 MiB reserve,
peaked at 53 MiB, and took 30 seconds.

The first active heartbeat reported `pk[entries=16129 capacity=26880
key_bytes=787265]`; these are cache counts and accounted key bytes, not RSS.
A collector for heights 600,000–600,127 and a health trace were armed for the
new PID: the collector used a 256 MiB cap / 256 MiB reserve, and the health
trace used a 128 MiB cap / 128 MiB reserve. Neither has a modern-chain sample
yet. Full IBD remains ongoing.

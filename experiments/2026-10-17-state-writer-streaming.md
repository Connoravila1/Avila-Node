# `state.dat` streaming rewrite probe

**Status:** bounded offline comparison passed on a cleanly stopped mainnet
v4 checkpoint. The writer implementation preserves the existing file format;
no consensus acceptance change is intended.

The captured input was at connected height 188,928, hash
`00000000000005400d9a675d37db5b2140887238fd1335db17cdb2159a1d6814`, with
971,817 headers. It was 92,105,283 bytes, SHA-256
`be0de17b70d78f5ea68d5990656d1d11f23ac1cc591392c28c7db0e3e7c94159`.
The example accepts only a regular v4 mainnet state no larger than 256 MiB,
validates it with `read_state`, and requires externalized coins with empty
inline UTXO and undo sections. It refuses an existing destination, overlapping
source/destination paths, and a source `state.dat.tmp`; it does not connect to
or write to node configuration/data directories.

`crates/avila-consensus/examples/checkpoint_rewrite.rs` runs the same bounded
read/decode in both modes. The default writes through the new 64 KiB buffered
streaming writer. `--buffered-reference` uses the previous v4 payload and
framing encoder. Each run writes only to a newly created destination directory
and reports height, header count, source/output byte counts, total elapsed
time, and Linux `VmHWM`. Compare the generated files byte-for-byte and by SHA-256.
`VmHWM` is the process's resident-set high-water mark; it does not measure
nonresident virtual allocations or cgroup file cache. Both runs include input
read/decode and are not an IBD or writer-only speed benchmark.

The native run first compiled the example separately under a 2,560 MiB cap
and 1,024 MiB reserve. It then ran each prebuilt mode in a separate process
under a 1,024 MiB cap and 1,024 MiB reserve, using distinct fresh destinations:

```sh
tools/guard_run.sh --max 2560 --reserve 1024 -- cargo build --release --locked -p avila-consensus --example checkpoint_rewrite
tools/guard_run.sh --max 1024 --reserve 1024 -- target/release/examples/checkpoint_rewrite <source-dir> <streaming-destination>
tools/guard_run.sh --max 1024 --reserve 1024 -- target/release/examples/checkpoint_rewrite <source-dir> <buffered-destination> --buffered-reference
sha256sum <streaming-destination>/state.dat <buffered-destination>/state.dat
cmp <streaming-destination>/state.dat <buffered-destination>/state.dat
```

Both output files were byte-for-byte identical to the captured source and had
the same SHA-256. The buffered-reference process took 1,540 ms and reported
`VmHWM` 273,520 KiB (about 267.11 MiB); the streaming process took 1,547 ms
and reported 182,796 KiB (about 178.51 MiB). The outer guard sampled 267 MiB
and 179 MiB respectively, with 2 seconds wall time for each. These are single
trials with different cache state and clock conditions; they do not support a
speed claim. The comparison includes the same read/decode and write work in
both processes and does not prove that all node RSS is fixed.

After installation, a clean shutdown/restart at 2026-10-17T06:25:04.548465Z
resumed at saved height 188,928 with the same checkpoint hash. The node then
advanced to height 190,895 with six connections, retaining PID 560505. Its
validation report still had no AssumeValid checkpoint and reported
`historical_scripts_required: true`. The attached GUI at 760×600 displayed
live heights 189,659 and later 190,819; closing its node window exited 0 while
PID 560505 continued to 190,895. That GUI check used a 512 MiB cap / 512 MiB
reserve, peaked at 54 MiB, and took 112 seconds. A modern-chain watcher for
heights 600,000–600,127 was rearmed under a 256 MiB cap; it has no result yet
because the node has not reached that range. IBD remains incomplete.

The reader still materializes the decoded state, and the chainstate caller
still creates its header/chain snapshot before invoking the writer. The
streaming serializer uses a 64 KiB buffer and reduces process high-water memory
in this bounded comparison; it does not make total checkpoint memory constant
or prove a production-wide RSS reduction. The v4 framing, payload bytes,
checksum coverage, and atomic temp-write/fsync/rename/directory-fsync sequence
remain unchanged. If directory fsync reports an error after rename, the new
file may already be visible and durability is indeterminate; rename cannot be
rolled back as though the old file were certainly preserved. No IBD speed or
validation-policy claim is made.

Validation passed: the full native pipeline completed in 324 seconds with a
2,560 MiB cap / 1,024 MiB reserve and 1,807 MiB peak. Workspace all-target
Clippy with GUI/devtools features and warnings denied, rustdoc with warnings
denied, 1,156 Rust tests (five ignored, zero failed), and 14 Python tests all
passed. Release CLI, GUI, and example builds passed, as did CLI
`check-config`/`inspect` and GUI help smoke checks. The first gate stopped on
unused example imports; those were removed before the full rerun. Installed
artifact SHA-256 values were CLI
`55aebb84f5c6d0344431c60323cdd60f317c391316d972bd45f256330647bfa5` and GUI
`5d183b6d54b186e956b6a790d5ba9955bf5e613b5ce9e16a8fa4b1f2a3fdf8a8`. The
validated source fingerprint was
`dc1039ca2928c074b17d76e9573000674369e4d25f19c420a6fde3fd032fd825`.

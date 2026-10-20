# Stored block branch prefetch — 2026-10-20

This change adds a chainstate-owned persistent pair of readers for stored
branch replay. It schedules the actual read order used by branch simulation:
disconnect the active tip to the fork, then reconnect the winning candidate.
The worker window is four requests, with at most 16 MiB of serialized frames
and a conservative 64 MiB decoded-body reservation. Larger bodies stay on the
ordinary synchronous `BlockStore::read` path. Worker jobs carry an immutable
store path, network magic, file position, expected block hash, and epoch.
Frame, decode, hash, and epoch failures fall back to the regular body read;
workers join their batch before the simulated state can be adopted or a flush
or prune can begin. Dropping chainstate joins the persistent readers.

`AVILA_BLOCK_PREFETCH=0` disables the pool; the default uses two readers. The
normal P2P tip-extension path receives an already-decoded `Block` from
`SyncManager::on_block` and does not benefit from disk prefetch. This change
targets stored-body branch activation only. It does not add download/decode
overlap, and no speedup is claimed before matched measurement.

## Matched diagnostic

Use the `stored_reorg_prefetches_disconnect_then_reconnect_bodies` fixture in
separate processes. It stores a two-block active chain and a three-block
candidate branch, fully validates the winning branch, and asserts the expected
tip plus five worker-cache hits (two disconnect bodies and three reconnect
bodies) when enabled. Alternate the arms after the test binary is built:

```sh
AVILA_BLOCK_PREFETCH=0 tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus chainstate::tests::stored_reorg_prefetches_disconnect_then_reconnect_bodies -- --exact
AVILA_BLOCK_PREFETCH=1 tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus chainstate::tests::stored_reorg_prefetches_disconnect_then_reconnect_bodies -- --exact
```

The small regtest fixture is a queue/overlap smoke test, not a performance
claim. For a useful storage comparison, replay a pinned stored side-branch
fixture large enough to amortize the process setup, on fresh identical store
copies. Report checked blocks, connect verdicts, resulting tip/UTXO state,
reader setting, disk traffic, CPU, peak memory, and wall time for both arms.
Do not use the regular tip-only `accept_probe` replay as evidence for this
change; it performs no stored-branch reads.

## Validation for the central serialized runner

```sh
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus blockprefetch::tests::queue_consumes_matching_bodies_and_falls_back_on_mismatch
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus blockprefetch::tests::stale_epoch_is_drained_and_drop_joins_readers
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus blockprefetch::tests::reservations_bound_window_and_decoded_bytes
AVILA_BLOCK_PREFETCH=1 tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus chainstate::tests::stored_reorg_prefetches_disconnect_then_reconnect_bodies
AVILA_BLOCK_PREFETCH=1 tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus chainstate::tests::rejected_prefetch_hash_falls_back_to_matching_store_body
AVILA_BLOCK_PREFETCH=1 tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus chainstate::tests::corrupt_prefetch_frame_falls_back_to_ordinary_store_error
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus
```

This delegated implementation has only been formatted and diff-checked; no
builds, tests, or timing runs were performed here.

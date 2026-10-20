# Coins pipeline changes — 2026-10-20

This change adds bounded parallel prevout reads and retains a bounded sample
of live values written by a flush as clean cache hits. It also removes
born-and-spent coins from the dirty map at mutation time, so flush no longer
scans the whole map to prune tombstones. Coins, undo, and the committed tip
still cross the backend boundary in the existing atomic commit.

The clean read cache and warm promotion set each have a 16 MiB byte budget and
a 4096-entry cap. During an in-flight flush, the old bounded warm set and new
dirty-window warm set can coexist; the resulting maximum of these three sets
is 48 MiB plus bounded FIFO metadata. Oversized script coins are skipped
without evicting useful entries. FIFO records carry generations so stale
invalidation records cannot remove a newer value for the same key.

No timing or speedup is claimed here. The implementation branch has not been
built or run under this delegated task; central validation is serialized by
the parent agent on the shared laptop.

The central runner selected a 4096 MiB hard cap with swap disabled and a
1024 MiB startup reserve after a measured-headroom audit and the user's
authorization to make all machine resources available to IBD. This is the
current audited choice for the 8 GiB laptop under its observed desktop load,
not a permanent user-set requirement; remeasure headroom before changing it.

## Matched harness

`accept_probe` replays stored blocks from a datadir copy through the production
accept path, enables the same speculative script pool as the node, sets
`assume_valid=None` (`assumevalid=0`), fails on block rejection, and drains all
script jobs before it returns. It then writes the normal durable checkpoint,
closes the chainstate, reopens it, and checks the tip hash/height, UTXO count,
coins backend tip, and a spendable coin from the saved tip block. Run each arm
against a fresh copy of the same fixture at the same `--start` and `--count`.
The baseline uses `AVILA_PREVOUT_WORKERS=0 AVILA_CLEAN_CACHE=0`; the candidate
uses `AVILA_PREVOUT_WORKERS=2 AVILA_CLEAN_CACHE=1`. The present prefetch waits
for its per-block workers before connect begins; it gets parallel backend
reads but does not overlap those reads with block application, and it includes
per-block thread-start cost. A later measured improvement could use a
chainstate-owned bounded worker queue: submit the block's read batch, connect a
small leading transaction prefix using the ordinary layered lookup while the
workers read, join the batch, then resolve the remaining transactions from
the prefetched results. Any such design must retain the current dirty,
flushing, run, and same-block lookup precedence, and join before every error,
flush, and reorg boundary.

Keep the same dbcache,
process guard, power mode, and competing load for both arms, and alternate run
order.

After building the harness once under the repository guard, run the binary:

```sh
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo build --release -p avila-consensus --example accept_probe
AVILA_PREVOUT_WORKERS=0 AVILA_CLEAN_CACHE=0 tools/guard_run.sh --max 4096 --reserve 1024 -- target/release/examples/accept_probe /path/to/fresh-copy-a --start 0 --count 301
AVILA_PREVOUT_WORKERS=2 AVILA_CLEAN_CACHE=1 tools/guard_run.sh --max 4096 --reserve 1024 -- target/release/examples/accept_probe /path/to/fresh-copy-b --start 0 --count 301
```

Use the complete pinned mainnet 301-block fixture/datadir segment for a
full-validation comparison. The harness reports acceptance wall time,
connection timing buckets, and backend writes; the guard reports process CPU,
peak memory, and outer wall time. Preserve both, plus the identical checked
block range, receipt/check counts, durable tip/state, cache setting, fixture
hashes, and host load in the result record. The current harness is a diagnostic
replay from an existing datadir, not a first-launch IBD measurement.

## Validation commands for the central runner

```sh
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus parallel_prevout_fetch_returns_hits_and_missing_keys
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus prefetched_prevouts_preserve_dirty_layer_and_input_boundaries
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus clean_backend_hits_survive_dirty_flush_and_mutations_invalidate_them
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus clean_cache_byte_budget_and_generation_safe_fifo
tools/guard_run.sh --max 4096 --reserve 1024 -- cargo test --release -p avila-consensus
```

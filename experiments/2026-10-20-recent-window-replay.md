# Recent-window full-validation replay probe (2026-10-20)

This records one qualified, controlled A/B pair for the measurement harness;
it is evidence about a warmed 128-block replay window, not a general performance
claim. The probe replays a contiguous range ending at a previously connected tip by invalidating the
first block in the range, then reconsidering it so normal best-chain
activation reconnects the range. `assume_valid` is disabled, speculative
script checks are drained before timing is accepted, and the final checkpoint
is reopened and compared against the initial tip, coin count, and complete
Core-compatible `hash_serialized_3` commitment.

The probe requires separate canonical `--source-dir` and `--work-dir` paths
and refuses aliased or nested paths. It never opens the source as a chainstate;
all mutation is confined to the supplied copy. Before disconnecting anything,
it requires the coins backend to be durably at the expected tip, verifies the
undo floor permits rewinding to the requested parent, checks every window body
is present and decodable, and verifies each persisted undo decodes and is
tagged with that height's active-chain block hash. A missing/pruned body, bad
undo, stale copy, or collected undo prefix aborts before replay begins.

The streaming UTXO commitment walks the ordered redb table. Because outpoint
keys encode `vout` little-endian, it buffers only one txid's outputs, sorts
that group numerically by vout, and feeds the canonical serialization into
incremental SHA256d. A malformed record, duplicate vout, oversized txid group,
or unordered hash-engine backend returns an error. A focused fixture test
compares this result with the existing in-memory canonical implementation.

Qualification uses two independent copies from the same stopped checkpoint,
never sequentially mutating one copy for both treatments. Both node and redb
coin caches were fixed at 256 MiB. The probe rejects any mismatched treatment
environment before scanning state. Example invocations (run through the
repository's guarded resource wrapper):

```sh
AVILA_PREVOUT_WORKERS=0 AVILA_CLEAN_CACHE=0 AVILA_BLOCK_PREFETCH=0 \
AVILA_COINS_CACHE_MB=256 \
  cargo run --release --locked -p avila-consensus --example replay_window_probe -- \
  --source-dir "$LIVE" --work-dir "$BASE_COPY" \
  --expected-tip-height 325897 --expected-tip-hash "$TIP_HASH" --count 128

AVILA_PREVOUT_WORKERS=2 AVILA_CLEAN_CACHE=1 AVILA_BLOCK_PREFETCH=1 \
AVILA_COINS_CACHE_MB=256 \
  cargo run --release --locked -p avila-consensus --example replay_window_probe -- \
  --source-dir "$LIVE" --work-dir "$CANDIDATE_COPY" \
  --expected-tip-height 325897 --expected-tip-hash "$TIP_HASH" --count 128
```

The first qualified pair used the stopped local mainnet checkpoint at height
325897, with a 128-block window (325770..=325897), undo floor 290118, full
script validation, `assume_valid=None`, node dbcache=256 MiB, redb cache=256
MiB, and a 4096 MiB guard cap with 256 MiB reserve. Both independent runs
reopened successfully and matched the exact tip, 14,248,193-coin count, and
full `hash_serialized_3` digest
`e8efca054a4f747ba55f139442f1b82e1f2e213c39ffcec7ccc02acc9bf94bfa`.

| Treatment | Workers / clean cache / block prefetch | Activate | Flush | Reopen | Final full UTXO hash | Total | Guard peak |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline A | 0 / 0 / 0 | 35.403 s | 1.911 s | 21.641 s | 62.657 s | 216.231 s | 3473 MiB |
| Candidate B | 2 / 1 / 1 | 37.804 s | 2.217 s | 21.587 s | 47.964 s | 210.184 s | 4095 MiB |

The qualified probe and its treatment-environment assertions are recorded in
commit `7ee8109`; the run receipts themselves do not capture an executable
hash, so the exact binary provenance cannot be reconstructed from these logs
alone. Both runs used the pre-change disk
prefetch decoded reservation cap of 64 MiB. The later 512 MiB cap admits two
maximum-size bodies but was not part of this A/B pair and has no performance
measurement yet.

The single pair is preliminary. Candidate total wall time was about 2.8% lower,
while activation itself was 6.8% slower. The guard's sampled maximum of cgroup
`memory.current` includes file cache and cannot be attributed to the replay
phase; the wrapper reads `memory.peak` only if no sample was captured. Sparse
process RSS samples ranged from roughly 0.5 to 1.42 GiB, but are
not a reliable phase maximum. This pair establishes neither a repeatable
improvement nor a whole-IBD speedup, and it does not demonstrate that the
candidate's higher cgroup peak came from anonymous process memory. The full-state
hashing/restore phases are included in total and are expensive relative to the
128-block activation. Initial A1 timings are
excluded: its post-flush reopen exposed a best-header-tip recovery bug, which
was repaired and covered by durable reopen tests. A subsequent A1-fixed run
validated state but used the default 1024 MiB redb cache, so it is excluded
from comparison. The qualified A/B pair was rerun with both cache sizes fixed
at 256 MiB. Guard receipts and complete logs are private under
`~/.local/state/avila-review/ibd-replay-{A-qualified,B-qualified}.log`.

For future repetitions, alternate treatment order and keep build, database
caches, CPU/resource cap, and filesystem conditions fixed. Record copy/setup
time separately from open, preflight, activation, script drain, flush, reopen,
and full-UTXO-hash times. The preflight and initial hash touch both block and
coin pages, so this is a warmed recent-window comparison, not a cold-start or
whole-IBD speedup estimate. Do not proceed if the undo floor is above the
selected parent; choose another fully retained window or report that no valid
window is available.

# Avila Node — agent operating rules

- **Bitcoin only.** Strict no-shitcoin policy, in any form: no other
  chains, assets, tokens, alternate consensus networks, or
  fork-evaluation infrastructure. See `docs/SCOPE.md` "Bitcoin only".
- Consensus rules are never configuration. Optimizations must preserve
  every check — hints are recomputed, never trusted; a slow path always
  exists.
- Claims require evidence: benchmark or live-wire test before asserting
  a win. Log experiments in `experiments/LOG.md`.
- Test protocol features on real connections, not only fixtures.
- Repo conventions: `cargo test --release -p <crate>`; docs in
  `docs/`, experiments in `experiments/`.
- **Resource limits (mandatory).** This is a 30 GiB laptop sharing a
  desktop. Any job that can grow unboundedly — corpus builders,
  snapshot loaders/verifiers, window joins with `--boundary`, node
  dumptxoutset runs, large file scans — MUST run under
  `tools/guard_run.sh`, which enforces a kernel-level cgroup
  `MemoryMax` (instant OOM-kill at the cap; no polling gap) and refuses
  to start without `MemAvailable >= cap + reserve`. Polling watchdogs
  are NOT sufficient (GB/s allocators beat any interval). Suggested
  caps: corpus build 8192, window_join w/ boundary 12288,
  snapshot_verify 2048. Never run two heavy jobs concurrently.

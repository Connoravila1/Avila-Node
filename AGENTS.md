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
- **Resource limits (mandatory).** This is an 8 GiB i5-9300H laptop
  sharing a desktop. Any job that can grow unboundedly — corpus
  builders, snapshot loaders/verifiers, window joins with `--boundary`,
  node dumptxoutset runs, large file scans, and heavyweight builds — MUST
  run under `tools/guard_run.sh`, which enforces a kernel-level cgroup
  `MemoryMax` and refuses to start without `MemAvailable >= cap +
  reserve`. Polling watchdogs are NOT sufficient (GB/s allocators beat
  any interval). The wrapper's 8192 MiB cap + 4096 MiB reserve defaults
  exceed this machine's physical-memory budget: never rely on them.
  Pass explicit `--max` and `--reserve` values chosen from current
  `MemAvailable` and a deliberate desktop reserve, then record the cap.
  The managed IBD service uses a 3072 MiB memory cap with swap disabled.
  Never run two heavy jobs concurrently.

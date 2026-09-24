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

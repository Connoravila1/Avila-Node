# Live network sync — signet proven end-to-end

**Date:** 2026-09-24 · **Status:** WORKS — block-fetch scheduling is the limiter

## Hypothesis

The consensus engine + p2p machinery can sync against real peers — the
credibility gate for every other claim.

## Method

`avila-node sync --config signet.toml --blocks N --timeout-secs T` —
DNS-seeded outbound peers, headers-first, full consensus intake through
`Chainstate` (no trusted paths).

## Results

| run | headers | connected | wall | peers |
|---|---|---|---|---|
| target 200 | 12,000 | 208 | 15.4s | 6-10 |
| target 2000 (resumed) | 66,000 | 1,124 | 639.6s (timeout) | ~75 cumulative, 4-8 live |

- First run: 208 real signet blocks downloaded and validated in 15.4s.
- Second run resumed from the persisted chainstate at height 208 —
  restart/resume works.
- Headers raced to 66k while connected lagged: ~1.7 blocks/s sustained.
  In-flight requests stayed 0-96 — the scheduler is conservative;
  peer churn (77 drops over the run) throttles block fetch.
- Validation itself was never the bottleneck: every accepted block
  connected immediately once downloaded.

## Findings

1. **The mechanism is proven**: real handshake, headers-first, block
   download, consensus connect, crash-safe resume — all against the
   live signet network.
2. **Block-fetch scheduling limits throughput**: in-flight stays low
   while headers soar — the scheduler under-parallelizes block download
   across peers. A fetch-side tuning pass (raise in-flight per peer,
   faster staller detection) is the next sync experiment.
3. **Signet ≠ mainnet caveat (honest)**: signet blocks are small and
   sparse — per-block validation cost here is trivial. The 1.7 blk/s
   rate is a *fetch* number, not a validation ceiling; fixture benches
   show connect at 94-520 blk/s. Mainnet-scale remains unproven until
   a real mainnet run.

# Experiment: speculative connect — cross-block script pipelining

**Date:** 2026-09-23 · **Status:** adopted (experiment-grade; daemon
not yet wired) · **Artifacts:** `connect::ScriptPool`,
`connect::BlockCheck`, `connect::connect_block_deferred`,
`Chainstate::enable_speculative_connect` / `drain_scripts`,
`pending_scripts` queue

## Hypothesis

Experiment #14 showed `connect_block` is ~95% script checks under a
hard per-block barrier (`run_script_checks` drains before the block
returns). A persistent script pool with a deferred wait lets block
N+1's serial phase + job submission overlap block N's drain.

## Mechanism

- `ScriptPool`: N (`available_parallelism`) detached workers draining
  a shared FIFO of owned `(tx, prevouts, flags)` jobs; each job
  decrements its block's `BlockCheck.remaining`.
- `connect_block_deferred` applies the block and returns
  `(undo, Arc<BlockCheck>)` instead of draining; `connect_block`
  keeps exact semantics by waiting + disconnecting on failure.
- `Chainstate.pending_scripts`: speculatively-applied tail, depth 8.
  `accept_block` pushes each block's handle and waits the oldest once
  the window fills. `drain_scripts` (and therefore `flush_coins`,
  which persists tip+undos) waits all pending.
- Failure path: a failed pending block drops itself and every pending
  block above it, `mark_invalid`, `rewind_connected(parent)` —
  identical end state to an inline drain failing.

## Result

625-block regtest fixture, ~26 tx/block of real signed P2WPKH spends:

| mode | wall | blocks/s |
|---|---|---|
| baseline | 3.0 s | ~205 |
| speculative | 1.2 s | **~520 (2.5×)** |

Correctness: `speculative_connect_matches_sequential` (identical
chain + UTXO), `speculative_failure_rewinds_pending_blocks`
(failed-script rollback + mark_invalid), full suite 469/469.

## Honest caveats

- **The 2.5× is density-flattered.** Per-block thread-spawn and drain
  barriers dominate at 26 tx/block; mainnet blocks (~3k tx) amortize
  spawn cost, so the expected gain on dense historical segments is
  the serial fraction (~4%) plus drain-tail slack — likely 5–15%.
  The mechanism is real; the magnitude on this fixture is the
  workload's, not mainnet's.
- `Connected` under the pool means *applied*, scripts pending —
  `drain_scripts` is the verified-tip boundary. RPC consumers must
  not read `connected` as verified until drained; daemon wiring
  deferred for exactly this reason.
- Pending depth 8 is untuned; deeper windows trade rollback cost
  against overlap.

## Follow-up

Re-measure on a denser fixture (~500+ tx/block) for the mainnet-shaped
number, then decide daemon wiring (`--spec-connect` flag) vs further
work on the dominant bucket itself (Schnorr batch verification).

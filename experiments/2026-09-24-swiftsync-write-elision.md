# SwiftSync write-elision — churn measurement

## Question

Core's SwiftSync (PR #34004) proposes never writing coins that die
before the sync checkpoint: maintain a hash aggregate
(`all outputs − all inputs = UTXO set`), verify it at the checkpoint,
persist only survivors. How much of the UTXO write load is actually
eliminable?

## Method

Parsed every block from the live signet node's blk files
(`/tmp/avila-data/signet/blk*.dat`, ~790MB, 183,884 blocks of real
signet traffic, Core-compatible framing). For every transaction:
recorded each created outpoint's birth height, matched each input
against the created set, measured lifetimes.

Tool: `tools/churn_scan.py` (pure-Python blk walker, computes stripped
txids, tracks outpoint birth→death).

## Result

| Metric | Value |
|---|---|
| Blocks parsed | 183,884 |
| Coins created | 5,460,466 |
| Coins spent (resolved) | 3,456,543 |
| **Created-then-spent within window** | **63.3% of all coins** |
| Still live at end | 2,003,923 |
| Median coin lifetime | **2 blocks** |
| Die same block | 47.0% of spends |
| Die ≤10 blocks | 61.9% |
| Die ≤100 blocks | 75.1% |
| Die ≤1000 blocks | 87.7% |

## Reading

**~63% of all coin writes during this sync were pure waste** — created
and deleted without ever being needed as live state. The churn is
heavily front-loaded: nearly half of all spending is same-block
(batching/consolidation patterns dominate signet traffic).

A SwiftSync path would:

1. Feed created+spent outpoints into a rolling 256-bit aggregate
   (a few SHA ops per input/output — cheap vs. a backend write).
2. Write only the ~37% of coins that survive to the checkpoint.
3. Verify `outputs − inputs = surviving set` at the boundary —
   the hints file is untrusted, a wrong one just fails the check
   and falls back to a normal path.

This is exactly our advice pattern: an untrusted accelerator (the
hints/survivor set) gated by a cryptographic check (the aggregate vs.
the computed UTXO set). Nothing about consensus verification is
skipped — script validation still runs on every input; only the
*storage* of doomed coins is elided.

## Caveats

- **Signet ≠ mainnet.** Signet's activity is dominated by test-app
  batching; mainnet churn ratios differ (likely similar order —
  Core's own motivation is that "the vast majority of coins created
  are later spent"). A mainnet fixture measurement is the follow-up.
- The win is *writes*, not validation: connect cost is dominated by
  script checks (per the ConnectTiming measurements, ~95%), so this
  attacks the disk-write tail, not the script-verification bulk.
- In-memory map of live coins during the window is still required —
  the aggregate can't answer membership queries; SwiftSync keeps a
  compact live set, it just doesn't flush the dead.

## Verdict

**Hypothesis confirmed; pursue the prototype.** 63% write elimination
on real network data is worth the machinery. Next step: a bench that
replays the fixture with the aggregate path — measure actual
wall-clock and disk-bytes deltas vs. the current backend.

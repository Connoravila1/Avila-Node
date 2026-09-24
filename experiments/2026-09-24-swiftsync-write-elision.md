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

## Fixture bench — where the win binds

`connect_bench` on the 625-block regtest fixture:

- **512MiB / 8MiB cache: zero backend writes** — the entire live set
  (~13k coins) fits in the write-back cache; nothing ever flushes.
  Storage share of connect time: ~3% either way. Scripts are 96%.
- **1MiB cache: 2 commits, 13,791 puts, 2,008 dels** — ~15% of backend
  writes were later deleted. Intra-flush elision already eats
  same-window churn; the 15% is the cross-window residue.

Honest reading: **the win binds only when the live set exceeds cache**
— mainnet IBD (170M coins vs ~0.5-4GB dbcache) flushes constantly, and
the signet churn data says ~63% of that flush traffic is doomed
coins. On a fixture small enough to cache, there is nothing to save.
That is the correct scoping: this is a mainnet-IBD optimization, not
a general speedup — same class as assumeutxo.

## Verdict

**Hypothesis confirmed; pursue the prototype.** 63% write elimination
on real network data is worth the machinery — but the payoff lives at
mainnet scale. Design note for the prototype: the hints file is
untrusted survivor data — wrong hints just fail the aggregate check
at the checkpoint and fall back to the normal path. Nothing about
consensus is skipped.

---

## Pass 2 — aggregate mechanics proven on the real chain (09-24, later run)

`swiftsync_bench` replays the node's own 229,113-block signet main
chain (70 side-branch blocks excluded by header indexing) maintaining
only a 256-bit wrapping-sum tag aggregate + a transient tag map:

- **22,445,304 coins created; 15,041,867 spent in-window;
  7,403,437 survivors** — **67.0% of creates never need disk** (the
  earlier 63.3% was Python-scan noise from out-of-order/orphan frames;
  chain-ordered replay is the honest number)
- **`created − spent == Σ survivor tags`, exactly**, over the whole
  chain — the multiset-hash math holds with zero drift at real scale
- **Fraud check fires**: dropping one survivor from the hinted claim
  breaks the equality — a lying hints file is detected at the
  checkpoint
- **Cost**: transient map peaks at 7.45M entries ≈ **682 MiB** at
  signet scale (mainnet IBD would need ~10-20× that — the known
  trade-off; Core's design hits the same wall)
- **Hints artifact**: 36 B/survivor outpoint list + aggregate
  commitment + height — **267 MB** for this chain. A consumer
  recomputes tags from its own transient coins and checks the
  commitment before trusting a single entry.

The scheme's three load-bearing claims all verified on real data:
the aggregate is exact, fraud is detectable, and the write win is
2/3 of coin ops. The remaining build is the sync-path integration
(hints producer RPC + consumer mode that keeps coins transient until
checkpoint).

---

## Pass 3 — protocol machinery shipped (09-24)

The aggregate + hints machinery is now in the consensus crate, not
just the bench:

- **`src/swiftsync.rs`**: `TagAgg` (256-bit wrapping-sum multiset
  hash), `coin_tag` (outpoint||coin commitment), `Hints` wire format
  (`AHS1 || height || aggregate || count || sorted outpoints`),
  `HintsVerdict`.
- **`UtxoSet` integration** (`connect.rs`): `enable_swiftsync` starts
  tracking `agg == Σ coin_tag(live)`; the invariant is maintained
  inside the three real mutation paths — `put` (tagged set-delta),
  `spend` (tombstone path), `remove_entry` (single sub of the visible
  coin, untagged tombstone to avoid double-subtracting a shadowed
  lower coin). `unoverlay(commit)` replays through `put` so reorg
  simulation adoptions note their tags; flushes don't touch the
  aggregate (they move the set, not its contents).
- **`swift_hold`** keeps `over_budget` false for the window —
  transient IBD is the actual optimization — released by
  `release_swiftsync_hold` at the checkpoint; tracking continues
  after (flushes preserve the invariant).
- **`emit_hints`/`verify_hints`**: producer artifact + consumer
  verdict (`Verified`/`AggregateMismatch`/`SurvivorMismatch`). Wrong
  hints can only waste the optimization — the node writes its own
  live set either way.
- **`Chainstate`**: `enable_swiftsync`/`release_swiftsync_hold`/
  `swiftsync_agg`/`emit_hints`/`verify_hints` passthroughs +
  `AVILA_SWIFTSYNC=1` opt-in inside `enable_coinsdb`.

Tests: `agg == Σ tags(live)` asserted after every mutation class
(create, spend, recreate-over-tombstone, live overwrite, lower-layer
spend, shadow put, `remove_entry`, overlay-commit, overlay-discard);
hints emit→encode→decode→verify round-trip; dropped survivor →
`SurvivorMismatch`; fabricated aggregate → `AggregateMismatch`;
malformed files reject without panic; the hold suppresses a real
backend's flush pressure and a real flush leaves the aggregate
untouched.

Sync integration + RPC (same commit): the sync loop releases
`swift_hold` when the connected height reaches the header tip (IBD
complete — the honest checkpoint); `emitswiftsynchints "path"` and
`verifyswiftsynchints "path"` expose the artifact and the consumer
verdict. A fourth test (`chainstate::tests::swiftsync_agg_tracks_real_connects`)
drives 106 real connects through `accept_block` and re-derives the
sum at every height — invariant holds including a real spend block.

Still open: the never-keep-full-coins variant that would shrink the
transient map (the 682MiB-at-signet cost — for mainnet IBD this
design needs a spool or a smaller per-coin footprint), and a live
end-to-end run where two nodes exchange a real hints file.

---

## Live-run finding — the transient map is the binding constraint (09-24)

Ran the real signet node (`AVILA_SWIFTSYNC=1`, synced 7.4M-coin set):

- **Enable-on-nonempty-set cost: ~6 minutes at 100% CPU + ~3.5GB RSS**
  — `iter()` walks all of redb, hashes every coin. One-time, but real.
- The node then re-entered IBD (94k blocks behind the new tip) with
  `swift_hold` keeping every new coin transient — RSS kept climbing
  and the box (30GB, ~12GB already pinned by tmpfs data) hit a device
  memory alert. Run stopped.
- A periodic-flush gap was found and fixed in the same pass: the sync
  loop's `FLUSH_INTERVAL` checkpoint called `cs.flush()`
  unconditionally — mid-window writes would have silently defeated
  the elision. Now gated on `cs.swiftsync_holding()`; explicit
  flushes (shutdown/checkpoint) still write.

Honest read: at signet scale the win is real (67% write elision,
exact aggregate, fraud detection) but **the transient set is the
cost** — ~96B/entry × live-set size held in RAM for the whole
window. For mainnet IBD (~170M coins) that is ~16GB before growth —
the same wall Core's SwiftSync hits. The design needs either a
committed-checkpoint cadence (smaller windows — checkpoint every N
blocks against the running aggregate, not just at tip) or the
leaner per-entry representation (the map stores full `Coin`s; a
swiftsync window only needs enough to validate spends — value +
script, which it already has — so the saving would come from
not-yet-spent hints driving *creation* elision, a bigger rewrite).

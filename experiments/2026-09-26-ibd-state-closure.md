# Gate 3 — exact state closure: occurrence-record engine vs `connect_block`

Experiment #77. 2026-09-26. Repaired per
`docs/IBD_SWE2_REVIEW_77_2026-09-26.md` (header-context continuation,
declared expectations, predicate isolation, record format).

## What changed in the repair pass (v2)

1. **Header context is now grown + checked on both engines.** The batch
   runner inserts each evaluated block's header into its own
   `HeaderTree` with asserted linkage (Ok + expected height), and a
   missing parent MTP is a hard error — no zero fallback. The supplied-
   state phase's frozen-tree defect is fixed: suffix headers extend the
   tree as the suffix evaluates.
2. **Declared expectations, not just agreement.** Every scenario carries
   `accept` or `reject@H` plus the expected last-valid tip; the oracle
   requires (a) both engines meet the declared outcome, (b) per-block-
   boundary canonical digests equal at EVERY height (rejection must
   preserve the prior digest), (c) tip hashes equal to each other AND to
   the expected block's hash in the selected chain.
3. **Supplied-state continuation asserts full-run equivalence:** both
   resumed exports and tips must equal the uninterrupted run's — and a
   second continuation exercises a *time-type* BIP68 spend of a coin
   created *after* the split (the frozen-tree bug's actual coverage gap).
4. **Predicate isolation fixtures added:** time-type BIP68 (early +
   satisfied), MTP-mode locktime (early + satisfied), non-final locktime
   satisfied, all-final bypass, fee-bearing coinbase claimed exactly and
   at +1, missing input, and an isolated BIP30 duplicate-creation case.
5. **BIP30 fixture notes:** identical coinbase txids are unreachable
   under active BIP34 by construction, so the case runs on a SYNTHETIC
   params clone with `bip34_height=u32::MAX` (regtest shape otherwise) —
   labeled synthetic, exercising pre-BIP34-era semantics full-IBD must
   implement. It immediately caught a real batch-engine hole: the
   dup-creation check only ran on non-coinbase txs, so a duplicated
   *coinbase* txid was accepted. Fixed — BIP30 now applies to every tx's
   outputs.
6. **Occurrence records are now explicit:** `Occ{height,txidx,idx}`
   positions on every creation/spend record; resolution is an ordered
   merge over those records (spend at position p sees only creations
   with pos < p, minus prior spends). Still sequential at block
   granularity — the honest description is "occurrence-aware per-block
   evaluator"; the corpus-wide partition/sort/join remains Gate 4's
   measured architecture.
7. **Artifact hygiene:** per-scenario canonical exports preserved
   (`gate3/*-inc.canonical`, `*-batch.canonical`), JSON output escapes
   strings properly, `first_diff` emits escaped record diagnostics, the
   summary field is labeled `genesis_hash`, fixture bytes and record
   count are separate fields.

## Result: 25/25 checks, exit 0

`experiments/results/gate3/state-join-2026-09-26.jsonl` — all scenarios
`ok=true`: expectations met, boundary digests equal at every height,
tip hashes equal to the selected chain, rejection preserves pre-block
state, supplied-state continuations reproduce the uninterrupted
terminal digest (`2e8cbd2d…`).

The 14 original cases are retained and extended to: valid window,
immature cb, cross-block + same-block double spends, future output,
in-block ordering, over-spend, excess reward, unspendable spend,
locktime early/satisfied/bypass/MTP-mode early+ok, BIP68 height early +
satisfied, BIP68 **time-type** early + satisfied (both plain and
post-split continuation), fee-claim exact + over-by-1, missing input,
isolated BIP30 duplicate-creation, supplied-state h105, supplied-state
with post-split time-locked spend.

## Honest scope (unchanged, now better-evidenced)

Correctness parity on bounded regtest chains with OP_TRUE scripts is
demonstrated for the listed predicates. Not covered: real script
verification bound to batch-resolved prevouts (Gate-1/2 plane),
UTXO-dependent sigop accounting, pre-BIP113 block-time finality, the
mainnet BIP30 exception heights (synthetic params exercise the
predicate; the exception table is mainnet-height-keyed), and any
historical mainnet segment — which additionally needs the checkpoint
boundary (last checkpoint block skipped) honored before use.

## Original (v1) description retained below for reference

## Question

Does the batch (occurrence-aware set-evaluation) architecture produce
*exactly* the same complete chainstate as the incremental path — not just
the same outpoint set — under every state predicate connect enforces?

## Two implementations

**Incremental (baseline)** — the real production path, in the real
order: `header insert` → `check_block` (context-free) →
`contextual_check_block` (finality/BIP113, BIP34, witness commitments,
weight) → `connect_block` (maturity, value conservation, dup-spend,
BIP30, sigops, script checks ON — `OP_TRUE` outputs verify trivially).

**Batch engine** — independent implementation
(`examples/state_join.rs`): per block, outputs are *created records*
keyed `(height, txidx, vout)` and inputs are *spend records* keyed
`(height, txidx, inidx)`; predicates are set operations over those
records — multiplicity (spent-key uniqueness), availability/ordering
(spend sees only creations at strictly earlier tx positions in-block,
plus the persistent set), maturity (coin.height + 100 ≤ height), value
conservation + fee aggregation → coinbase bound, unspendable exclusion
(`is_unspendable` outputs never enter the set), dup-creation (BIP30).
Lock/sequence semantics reuse the *shared rule helpers* both engines
must implement identically: `is_final_tx` (BIP113 cutoff) and
`bip68_locks_satisfied` (height + MTP locks via ancestor lookup) — the
spent-coin list feeding it comes from the batch engine's own ordered
resolution. `check_block`/`contextual_check_block`/`check_transaction`
are likewise shared: the experiment isolates the **state model**, not
the tx-level rule wording (which is fixed by consensus anyway).

What differs: the incremental path resolves inputs by querying a live
utxo map during tx iteration; the batch path resolves by overlay/persistent
record lookup with positional ordering and applies block-granularity
deltas (created minus same-block-spent → insert; spent → remove).

## Canonical comparison

`UtxoSet::iter()` / the batch map → sort by `(txid, vout)` → serialize
each record `txid(32B)‖vout(u32le)‖value(i64le)‖scriptlen(u32le)‖script‖
height(u32le)‖coinbase(u8)` → compare byte-for-byte + SHA-256 digest.
On mismatch the harness emits `first_diff` (byte offset, record index,
both decoded records). Database files are never compared.

## Battery and result

`cargo build --release -p avila-consensus --example state_join && ./target/release/examples/state_join`
→ `experiments/results/gate3/state-join-2026-09-26.jsonl` — **14/14
cases `state_equal=true` AND identical accept/reject verdicts**:

| case | verdict agreement | exercises |
|---|---|---|
| `valid_window` | accept h108 | mature spends, in-block chained spend (earlier-tx output), OP_RETURN output created+unspent, satisfied locktime |
| `immature_coinbase` | reject h104 | cb depth 99 < 100 |
| `double_spend_cross_block` | reject h106 | same outpoint spent twice across blocks |
| `double_spend_same_block` | reject h105 | same outpoint twice in one block |
| `future_output` | reject h105 | spend of an outpoint created only later |
| `same_block_order_bad` | reject h105 | spend of a *later* tx's output in-block |
| `wrong_amount` | reject h105 | outputs > inputs |
| `excess_reward` | reject h105 | cb pays subsidy+1 |
| `unspendable_spend` | reject h106 | spending a provably-unspendable (OP_RETURN) outpoint |
| `locktime_early` | reject h105 | non-final locktime (contextual BIP113 path) |
| `dup_txid_unspent` | reject h106 | BIP30 overwrite of unspent output |
| `seq_lock_early` | reject h107 | BIP68 height lock, coin h106 + lock 5 > h107 |
| `seq_lock_satisfied` | accept h108 | same coin, lock 1 at h107 OK |
| `supplied_state_h105` | accept h108 | fixture state injected at h105 (`insert_synthetic`), continuation identical — digest equals the full-run digest `2e8cbd2d…` |

Every digest pair matches; e.g. `valid_window` = 109 records / 5,778
canonical bytes / `2e8cbd2d56326b…` on BOTH engines. The supplied-state
phase reproduces the full-run terminal state exactly from the h105
export — fixture injection is honest (heights + cb flags preserved;
creation-MTP zeroed, and no time-locked inputs are exercised in that
phase — recorded limitation).

## Bugs this caught in my own batch engine (before first green run)

1. **Locktime polarity inverted** — I treated all-final sequences as
   *requiring* the lock to be reached; Core makes all-final inputs
   bypass `nLockTime` entirely. Caught because `locktime_early` showed
   incremental *accept* where batch rejected. Now both run the shared
   `is_final_tx`.
2. **Same-block create-and-spend leaked a survivor** — a coin created
   and consumed inside one block stayed in `created` and would have
   entered the live set. Fixed by the explicit anti-join
   `created \ spent` at commit.
3. **Coinbase bound checked before fee accumulation** — moved post-loop.

These are exactly the class of defects the byte-exact comparison exists
to find — set overlap would have passed all three.

## What this establishes — and its honest scope

- The occurrence-aware batch state model is **behaviorally equivalent
  to the incremental path on this bounded suite** — complete records,
  identical verdicts, including supplied-state continuation.
- Scope limits, stated: ~108-block regtest chains with OP_TRUE scripts;
  script verification itself is the Gate-1/2 plane (not re-proven here);
  BIP30 "create-after-fully-spent allowed" is unreachable post-BIP34 and
  noted rather than exercised; the time-based BIP68 branch runs through
  the shared helper with real tree ancestors on the batch side.
- This is the **correctness gate passing** — a precondition for asking
  whether the architecture materially advances the one-hour objective.
  Performance measurements on this model come next and only after this.

## Diagnostics retained

`experiments/results/gate3/state-join-2026-09-26.jsonl` — one record per
scenario: both tips, both rejection strings, state byte-length, record
count, both digests, per-engine wall ms (batch ~0.2-0.3 ms vs
incremental ~0.7-2.1 ms at 105-108 blocks — *diagnostic only at this
scale*, not a performance claim).

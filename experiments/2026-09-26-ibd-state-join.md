# Candidate 42 — exact UTXO-state derivation as a batch anti-join

Date: 2026-09-26. Status: measured on a bounded span; shape validated, full-
chain scale extrapolation only. `tools/ibd_state_ledger.py`, all files
`data/mainnet` (read-only), heights ~337k–342.2k (10 files, ~4,600 blocks).

## Question

Can exact UTXO-set state be derived as a batch set anti-join over
created/spent ledgers — replacing the serial per-connect UTXO mutation loop?

## Ledgers (sequential-write shape — the production cost model)

| ledger | record | entries | bytes |
|---|---|---|---|
| created.bin | txid32+vout32+value64+height32 = 48 B | 7,241,145 | 348 MB |
| spent.bin | txid32+vout32+height32 = 40 B | 6,656,451 unique | 266 MB |

## Join result (in-memory dict — bounded span only)

| class | count | share |
|---|---|---|
| consumed-created-in-span | 5,592,555 | **77.2% of created die within ~5 weeks** |
| outflow-to-history (cold-start deps) | 1,063,896 | 16.0% of spends |
| survivors at span end | 1,648,590 | 22.8% of created |

## Findings

- **The 77% die-young class is confirmed at mainnet scale, independently of
  the SwiftSync measurement** — created-then-spent-in-window never needs to
  touch a UTXO store under a join model; a windowed existence aggregate or
  the anti-join itself absorbs them.
- **Outflow-to-history (16%) is the cold-start dependency made explicit**:
  these spends need prevouts created before the span — in the #41
  architecture that's the txid index over prior history; in a full-IBD
  pipeline it's "everything before the replay window". Either way it's an
  index lookup, not maintained OLTP state.
- **Byte volumes bound the I/O**: at this era's density, full-chain scale
  (~2.7–3.0B created) → ~130–145 GB created + ~115–120 GB spent ledgers —
  sequential throughout; external sort-merge join is the production shape.
  Survivor materialization emits only the tail (~20–25% of created) — an
  ~8 GB UTXO-equivalent written once vs ~3B random mutations.
- The join's correctness relies on the same occurrence/ordering model
  validated by #74's zero-failure script replay.

## Caveats

- In-memory dict join, not the external sort — full-chain memory needs the
  sorted/partitioned variant (or ~40–60 GB RAM for a naive set).
- Maturity predicates (coinbase spend ≥ +100 heights) and
  BIP30-duplicate semantics are accounted in the occurrence model of
  `ibd_corpus_window.py` but not separately reported here — follow-up.
- Single era (h~340k); survivor share varies by era.

## Corrections (post-audit, experiment 75)

- The join used sets: duplicate-spend multiplicity, creation/spend
  ordering, coinbase maturity, and BIP30-duplicate rules were NOT
  implemented; survivor records lack scriptPubKey/coinbase metadata.
  "77.2% die in-span" is a set-overlap statistic on the selected
  records — it does not prove an exact-state algorithm or a
  whole-history survivor fraction.
- The 16% outflow class must be read as "source absent from selected
  records" — the input files are not demonstrated contiguous; it is
  not all older history.
- The 614 MB figure covers ledger writes only — not input scans,
  partition/sort traffic, reads, or survivor materialization.
  Extrapolated 20–25% survivors / ~8 GB chainstate are NOT established
  by this fixed-record sample.
- The occurrence resolver's maturity/dup claim ("accounted for by the
  corpus resolver") was unsupported — the join never invoked it.
- Gate 3 (exact-state comparison vs incremental baseline on a defined
  starting state + contiguous selected chain) remains open.

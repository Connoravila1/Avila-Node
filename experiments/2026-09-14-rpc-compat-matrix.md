# Experiment: field-level RPC compatibility against Knots 29.3

Status: complete (first matrix; ongoing coverage grows with the surface)

Roadmap gate/workstream: G4 — "a tested Core RPC compatibility matrix"

Scorecard rows: C1 (correctness evidence — the RPC surface is a
verdicts surface: identical inputs must produce identical answers).

Operating profile: `avila-node run --connect` + `--rpc` on regtest,
cookie auth, against a live Knots 29.3.0 regtest daemon.

## Question and hypothesis

Does the JSON-RPC surface return Core-compatible responses — same
method names, same parameter shapes, same field names, same value
formats — for the methods implemented? The matrix exists to catch
drift: any `DIFFERS` verdict on a shared field is a compatibility bug.

## Baseline and candidate

- Baseline: `bitcoind` Knots 29.3.0 (`/Satoshi:29.3.0/Knots:20260508/`)
  regtest, datadir `target/p2p-interop/datadir`, RPC `:58321`.
- Candidate: `avila-node` @ commit under test, regtest, RPC `:18443`,
  synced to the same chain tip (h120 at measurement).
- Both endpoints authenticated via Core-format `.cookie` over HTTP
  Basic — the same code path on both sides.

## Workload and method

`tools/compare_rpc.py` calls 20 methods with identical parameters on
both endpoints (block hash and a coinbase txid resolved live at the
shared height), flattens each response to field paths, and reports
matched / expected-dynamic / differing / one-side-only fields.
`DYNAMIC_KEYS`/`DYNAMIC_METHODS` mark legitimately node- or
time-specific values (time, curtime, peers, uptime, help text).

Reproduce:

```
avila-node run --connect <core-p2p> --rpc 127.0.0.1:18443
python3 tools/compare_rpc.py \
    --avila-cookie data/regtest/.cookie \
    --core-cookie <core-datadir>/regtest/.cookie --height 100
```

## Results

13 MATCH (every shared field byte-identical), 6 EXPECTED-DIFF
(presence gaps only), **0 DIFFERS** — no shared field disagrees in
value. One AVILA-ERROR (`estimatesmartfee` — honest "insufficient
data" on a fresh chain with no confirmation samples; Knots returned
its fallback). One BOTH-ERROR (`getrawtransaction` — neither side
indexes arbitrary txids; consistent behavior).

Exact matches include `getblocktemplate` — all 22 fields identical
including `rules: ["csv","!segwit","taproot"]`, `vbrequired`,
`vbavailable`, `longpollid` (tip+height) and the zero-witness-root
`default_witness_commitment` every post-segwit block carries —
plus `getblock` verbosity 1 (20 shared fields), `getblockheader`
(15), `getchaintips`, `getrawmempool`, `getconnectioncount`,
`getorphantxs`, `getblockcount`, `getbestblockhash`, `getblockhash`.

### Documented gaps (presence-only, never wrong values)

- `gettxout`: `scriptPubKey.asm`/`type`/`address`/`desc` — needs a
  script classifier + address encoder (not yet implemented).
- `getmempoolinfo`: `maxmempool` (our pool is entry/weight-capped,
  not byte-capped) and Knots-specific policy knobs (`rbf_policy`,
  `truc_policy`, `fullrbf`, `dustdynamic`, `dustrelayfee*`,
  `incrementalrelayfee`).
- `getpeerinfo`: byte counters, ping times, `lastsend`/`lastrecv`,
  per-height `inflight` list — per-peer telemetry we don't track.
- `getnetworkinfo`: `localaddresses` — we don't track our own
  advertised addresses.
- `getmininginfo`: `currentblocksize`, `networkhashps` — the latter
  needs a 256-bit work-diff divide not yet implemented.
- `getblockchaininfo`: we add `localobservation`/`peers` (honest
  extras; Core clients ignore unknown keys).

### Known semantic differences

- `estimatesmartfee` errors when the sample set is empty rather than
  returning a floor — the estimator only reports rates it observed.
- `getrawtransaction` requires a named block for non-pool txs; no
  txindex (same failure mode as Core without `txindex=1`).
- `stop` exists beyond Core's read set; everything else is read-only.

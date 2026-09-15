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

`tools/compare_rpc.py` calls 24 methods with identical parameters on
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

21 MATCH (every shared field byte-identical), 2 EXPECTED-DIFF
(presence gaps only), **1 DIFFERS** — `fullrbf` reports `false` vs
Knots' `true`: a genuine policy divergence, not a serialization bug.
Our pool enforces BIP125 opt-in signaling for replacements; Knots 29
ships mempoolfullrbf semantics. One AVILA-ERROR (`estimatesmartfee` —
honest "insufficient data" on a fresh chain with no confirmation
samples; Knots returned its fallback). `sendrawtransaction` error
paths match: `-22` decode failures, `-26`/`bad-cb-length` consensus
rejects. One BOTH-ERROR (`getrawtransaction` — neither side indexes
arbitrary txids).

`sendrawtransaction` was also verified live end-to-end (outside the
static matrix since pool state is per-daemon): a wallet-signed tx
submitted only to Avila was admitted to our pool and relayed via inv
to Knots, which fetched and pooled it; an already-pooled resubmit
returns the txid silently (Core's idempotent-broadcast behavior);
`maxfeerate=0` means unlimited (Knots accepted a 0.01-BTC-fee tx we
initially rejected); a capped fee returns `-25` "Fee exceeds maximum
configured by user (e.g. -maxtxfee, maxfeerate)"; a valued OP_RETURN
output over `maxburnamount` returns `-25` "Unspendable output exceeds
maximum configured by user (maxburnamount)" — both byte-identical to
Knots.

Exact matches now include the full display layer: `decodescript` on
P2PKH, taproot, unknown-witness, and nonstandard scripts returns
byte-identical `asm`, `desc` (with the descriptor polymod checksum),
`type`, `address`, and the nested `p2sh`/`segwit`/`p2sh-segwit` wrap
addresses — including `wsh(multi(...))` inner descriptors and the
v0-program length rule (a v0 program outside 20/32 bytes is
`nonstandard`, matching Solver). `gettxout` (9 fields), `getblock`
verbosity 2 (29 fields incl. per-tx `hex` and decoded
`scriptPubKey`/`scriptSig`), `getblocktemplate` (22), `getmininginfo`
(11 — incl. `networkhashps` computed through 256-bit chainwork
division, `currentblocksize/weight/tx` from a live template build),
`getblockchaininfo` (13), `getblockheader` (15), `getblock` (v1: 20,
v0: raw hex), `getchaintips`, `getrawmempool`, `getconnectioncount`,
`getorphantxs`, `getblockcount`, `getbestblockhash`, `getblockhash`.

### Documented gaps (presence-only, never wrong values)

- `getpeerinfo`: telemetry landed — `bytesrecv`/`bytessent`,
  per-command `*_per_msg` histograms, `conntime`/`lastsend`/`lastrecv`,
  `last_block`/`last_transaction`/`lastannounce` (emitted once the
  events exist, matching Core's conditional), `session_id`, ping RTT
  (`pingtime`/`minping`/`pingwait`), `synced_headers`/`synced_blocks`
  heights, per-height `inflight`, `addr_processed`/`addr_rate_limited`,
  `network`, `permissions`, `bip152_hb_*`, `minfeefilter`,
  `addr_relay_enabled`, `transport_protocol_type`, `presynced_headers`.
  Remaining C-ONLY fields are direction-asymmetric (`addrbind`,
  `addrlocal` — each daemon sees the other as the opposite direction)
  or Knots extensions (`cpu_load`, `forced_inbound`,
  `last_block_announcement`).
- `getnetworkinfo`: `localaddresses` — we don't track our own
  advertised addresses.
- `getmempoolinfo`: `maxmempool` (our pool is entry-capped, not
  byte-capped) and Knots-specific knobs (`rbf_policy`, `truc_policy`,
  `dustdynamic`, `dustrelayfee*`).

### Known semantic differences

- `fullrbf`: `false` — we implement BIP125 opt-in signaling; Knots
  29 enables full RBF. Real policy divergence to decide on.
- `estimatesmartfee` errors when the sample set is empty rather than
  returning a floor — the estimator only reports rates it observed.
- `getrawtransaction` requires a named block for non-pool txs; no
  txindex (same failure mode as Core without `txindex=1`).
- `stop` and `sendrawtransaction` are the only mutating methods;
  `sendrawtransaction` admits to our pool and relays to peers.

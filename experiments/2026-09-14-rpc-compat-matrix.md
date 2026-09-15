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
  synced to the same chain tip (h121 at measurement — see the
  `submitblock` paragraph; the matrix itself grew the chain).
- Both endpoints authenticated via Core-format `.cookie` over HTTP
  Basic — the same code path on both sides.

## Workload and method

`tools/compare_rpc.py` calls 31 methods with identical parameters on
both endpoints (block hash, coinbase txid, raw block hex, and raw tx
hex resolved live at the shared height), flattens each response to
field paths, and reports
matched / expected-dynamic / differing / one-side-only fields.
`DYNAMIC_KEYS`/`DYNAMIC_METHODS` mark legitimately node- or
time-specific values (time, curtime, peers, uptime, help text).

Reproduce:

```
avila-node run --connect <core-p2p> --rpc 127.0.0.1:18443 --txindex
python3 tools/compare_rpc.py \
    --avila-cookie data/regtest/.cookie \
    --core-cookie <core-datadir>/regtest/.cookie --height 100
```

## Results

46 MATCH (every shared field byte-identical), 2 EXPECTED-DIFF
(presence gaps only), 3 DIFFERS — one is a genuine policy divergence
(`fullrbf`: our pool enforces BIP125 opt-in signaling; Knots 29 ships
mempoolfullrbf semantics) and two are environmental (`getpeerinfo`,
`getconnectioncount` — the daemons hold different peer sets).
`estimatesmartfee` now returns Core's no-data result object
(`{"errors": ["Insufficient data or no feerate found"], "blocks": 0}`)
and its full argument-validation table (`-3` type, `-8` range,
case-insensitive `estimate_mode`). One CORE-ERROR
(`getrawtransaction` on a buried coinbase — a flag asymmetry: Knots
runs without `-txindex`, we run with it, so the bare-txid lookup
resolves only on our side; `getindexinfo` likewise reports `txindex`
only on the node that has it). `sendrawtransaction` error
paths match: `-22` decode failures, `-26`/`bad-cb-length` consensus
rejects. `savemempool` matches (`{"filename": <abs path>}`) and the
pool survives restart: `mempool.dat` is written on shutdown, entries
re-admit through full policy on start, spent-input entries are
skipped. `decoderawtransaction`, `gettxspendingprevout`, and
`getindexinfo` are byte-identical across their success paths and
every error class — including the `-1` help-text throws Core raises
for missing or excess arguments.

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

`submitblock` closes the mining loop end-to-end: a block assembled
from our `getblocktemplate` output (BIP34 coinbase, witness
commitment, correct merkle root, regtest nonce grinding) was
submitted through our RPC, connected to our chainstate, and announced
to Knots — which accepted it as the valid tip. Both nodes reported
h121 `3e696862313319ec73cf5cbf1963b3ca2f3d12a3e1569f2bf6fb9cee080b2004`.
Status strings match Core: `null` on connect, `"duplicate"` on
resubmit, `-22`/`Block decode failed` on undecodable input. The run
also surfaced a template bug now fixed: `build_template` wrote the
BIP34 height as a bare `OP_N` push, a 1-byte scriptSig at heights
1–16 — below the consensus coinbase minimum (`bad-cb-length`). Core's
`CScript() << nHeight << OP_0` appends a trailing `OP_0`; the
template now does the same.

The rest of Core's mining surface then landed, verified live against
Knots: `generatetoaddress` mined h122–h124 through our RPC (address →
scriptPubKey via the new base58check/bech32/bech32m decoder), each
block announced and accepted by Knots as tip; `generateblock` mined a
pooled tx by txid reference and returned `{"hash": …}` (raw-hex
entries are admitted to the pool first, matching Core's temp-pool
step); `submitheader` returns `null` for a known header,
`-25`/`Must submit previous header (…) first` for an orphan, and
`-22`/`Block header decode failed` for undecodable input. Error
paths verified byte-identical against Knots: `-5 "Error: Invalid
address"` / `"Error: Invalid address or descriptor"`,
`-5 "Transaction <txid> not in mempool."`, `-22 "Transaction decode
failed for <s>. Make sure the tx has at least one input."`.
`generateblock`'s `output` accepts an address or a descriptor subset
(`addr`/`raw`/`pk`/`pkh`/`wpkh`/`tr` key-path/`rawtr`, `#checksum`
verified); `tr()` applies the real BIP341 x-only tweak.

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

`getblockstats` landed at full parity (all 31 fields): the
`hash_or_height` selector replicates Core's `ParseHashV` errors
("hash_or_height must be of length 64 (not N, for '…')" / "must be
hexadecimal string"), the optional `stats` filter projects the
requested keys, and per-block fee/size/UTXO aggregates use the active
chain's undo data (`undo.txs[i]` is indexed including the coinbase).
Verified byte-identical against Knots at h100/h120 and at a
fee-bearing h124, including the five feerate percentiles and both
`utxo_size_inc` variants.

Serving genesis surfaced two deeper compat fixes:

- `Params::genesis_block()` now reconstructs Core's
  `CreateGenesisBlock` output per network — the shared
  `push(486604799) << push(4) << push(msg)` scriptSig (mainnet nBits
  is hardcoded even on regtest) with the "Times 03/Jan/2009" coinbase
  for mainnet/testnet3/signet/regtest and testnet4's own message plus
  its 33-zero-byte push + `OP_CHECKSIG` output. `Chainstate::body()`
  falls back to it for the genesis hash, so `getblock 0` /
  `getblockstats 0` / verbosity-0 hex are byte-identical to Core even
  though the body is never stored. The constructor returns `None`
  when the rebuilt coinbase doesn't anchor `genesis_header`'s merkle
  root (custom params), so it can't serve a wrong block.
- Core's UniValue serializes doubles through
  `std::setprecision(16)` — C `%.16g`, not shortest-round-trip. Two
  observable differences: a value needing 17 digits emits as a
  *different* double (regtest `difficulty`: `4.656542373906925e-10`
  vs the exact `…9247e-10`), and integral values print without a
  decimal point (`1`, not `1.0`). `core_num()` reproduces both, and
  now wraps `difficulty`, `verificationprogress`, and
  `networkhashps`. `getdifficulty` was also added (tip difficulty,
  Core's mining RPC).

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

`decoderawtransaction`, `gettxspendingprevout`, and `getindexinfo`
landed, along with three display/validation fixes the comparison
surfaced:

- `decoderawtransaction` shares `TxToUniv` but omits the `hex` echo
  (Core only attaches it for `getrawtransaction`/getblock-v2) and
  honors `iswitness`: absent tries no-witness then witness, `false`
  pins `Transaction::decode_no_witness`, `true` pins the witness
  decode. Bad hex or undecodable bytes are `-22 "TX decode failed"`.
  Missing or excess args are Core's `-1` help throw — the method's
  verbatim `RPCHelpMan` text is embedded and returned.
- `gettxspendingprevout` validates with Core's full error taxonomy:
  `-1`+help for missing/excess args, `-3` `Wrong type passed` /
  field-type / `Missing txid|vout`, `-8` for `outputs are missing`,
  `vout cannot be negative`, and the txid-length/hex gates, `-1`
  `JSON integer out of range` for non-integer or >i32 vouts. Lookups
  use `Mempool::spent_by`'s outpoint index — no pool scan.
- `getindexinfo` reports `txindex` (synced + `best_block_height`)
  only when `-txindex` is on, supports the `index_name` filter, and
  returns `{}` otherwise — matching Core's behavior per config.
- `TxToUniv`'s `scriptSig.asm` now runs `ScriptToAsmStr` with
  `fAttemptSighashDecode`: strict-DER pushes ending in a defined
  hashtype render as `…[ALL]`/`[NONE]`/`[SINGLE]`/`[…|ANYONECANPAY]`
  (undefined-last-byte sigs stay plain hex). `Script::asm_sighash`
  does this; `scriptPubKey.asm` keeps the plain mode.
- `txinwitness` is emitted for coinbase inputs too (witness
  coinbases carry the reserved value) and now precedes `sequence`,
  matching `TxToUniv` field order.
- `estimatesmartfee` was fixed end-to-end: no-data returns Core's
  result object `{"errors": ["Insufficient data or no feerate
  found"], "blocks": 0}` instead of an RPC error, `conf_target` is
  range-checked 1–1008 (`-8`), non-numeric targets are `-3`, and
  `estimate_mode` accepts unset/economical/conservative
  case-insensitively (`FeeModeFromString`).
- `getnetworkhashps` landed with Core's two-arg form (`nblocks`,
  `height`): `-1` selects the since-last-retarget window
  (`height % interval + 1`), windows clamp to the block's height,
  `height=-1` resolves to the tip, and the result goes through
  `core_num` (`%.16g`). The shared `network_hashps` helper also
  fixed `getmininginfo`'s stale below-120-returns-0 shortcut.

### Known semantic differences

- `fullrbf`: `false` — we implement BIP125 opt-in signaling; Knots
  29 enables full RBF. Real policy divergence to decide on.
- `getindexinfo`/`getrawtransaction` differences against Knots are
  flag-driven: our test node runs `--txindex`, the Knots instance
  does not. Both sides answer correctly for their configuration.
- `getrawtransaction` without a named block now goes through the
  `-txindex` index when enabled (`run --txindex`); without it the
  error is Core's exact `-5` ("No such mempool transaction. Use
  -txindex or provide a block hash …"). Index hits report
  `in_active_chain` and active-only `confirmations` like Core.
- Mutating methods are `stop`, `sendrawtransaction`, `submitblock`,
  `submitheader`, `generatetoaddress`, `generateblock` — the pool
  admission, block connect, and tip-announce paths are all live.

# Experiment: field-level RPC compatibility against Bitcoin Core and Knots

Status: complete (first matrix; ongoing coverage grows with the surface)

Roadmap gate/workstream: G4 — "a tested Core RPC compatibility matrix"

Scorecard rows: C1 (correctness evidence — the RPC surface is a
verdicts surface: identical inputs must produce identical answers).

Operating profile: `avila-node run --connect` + `--rpc` on regtest,
cookie auth, against live regtest reference daemons.

## Reference daemons

- **Primary: Bitcoin Core 29.4** (`bitcoin-29.4.tar.gz`, SHA256SUMS-
  verified) — the authoritative target. Regtest-only, `-txindex`,
  datadir `data-core-ref/`, P2P `127.0.0.1:58341`, RPC `127.0.0.1:58321`.
- **Secondary: Bitcoin Knots 29.3.0** (`/Satoshi:29.3.0/Knots:20260508/`)
  — kept for cross-checking, but Knots-specific behavior is *not*
  Bitcoin evidence. Knots fields/extensions absent from Core are
  treated as Knots-isms, not compat targets.
- Spot-check: **Core 31.1** (`data-core31-ref/`, RPC `127.0.0.1:58323`)
  to distinguish "upstream field added after 29.4" from "Knots-only".

Newer Knots carries divergent deployment rules (BIP110 was rejected by
Bitcoin and its supporters split onto a separate network), so Core —
not Knots — decides what "Bitcoin-compatible" means. All regtest-only:
no mainnet IBD, negligible disk/CPU.

## Question and hypothesis

Does the JSON-RPC surface return Core-compatible responses — same
method names, same parameter shapes, same field names, same value
formats — for the methods implemented? The matrix exists to catch
drift: any `DIFFERS` verdict on a shared field is a compatibility bug.

## Baseline and candidate

- Baseline: `bitcoind` Core 29.4 regtest (primary) and Knots 29.3.0
  regtest (secondary).
- Candidate: `avila-node` @ commit under test, regtest, synced to the
  same chain tip (h160 vs Core 29.4; h121 at first measurement — the
  matrix itself grows the chain).
- All endpoints authenticated via Core-format `.cookie` over HTTP
  Basic — the same code path on both sides.

## Workload and method

`tools/compare_rpc.py` calls 35 methods with identical parameters on
both endpoints (block hash, coinbase txid, raw block hex, and raw tx
hex resolved live at the shared height), flattens each response to
field paths, and reports
matched / expected-dynamic / differing / one-side-only fields.
`DYNAMIC_KEYS`/`DYNAMIC_METHODS` mark legitimately node- or
time-specific values (time, curtime, peers, uptime, help text).

Reproduce (Core 29.4 as reference; keep datadirs on the home
filesystem — /tmp tmpfs quota has already bitten once):

```
bitcoind -regtest -datadir=<repo>/data-core-ref -server \
    -rpcport=58321 -port=58341 -bind=127.0.0.1:58341 \
    -daemon -txindex -listenonion=0
# inside Core: createwallet, then generatetoaddress 160
avila-node run --config <cfg: data_dir=<repo>/data-core> \
    --connect 127.0.0.1:58341 --rpc 127.0.0.1:18444 --txindex
python3 tools/compare_rpc.py \
    --core 127.0.0.1:58321 --avila 127.0.0.1:18444 \
    --avila-cookie data-core/regtest/.cookie \
    --core-cookie data-core-ref/regtest/.cookie
```

## Results

Latest run vs **Core 29.4** at h160: 63 MATCH, 2 EXPECTED-DIFF
(`getpeerinfo` per-peer field shape — our extra observability fields
vs Core's direction-specific `addrbind`/`addrlocal`/`last_block`;
`getrawtransaction`'s `in_active_chain` — an upstream field added
after 29.4, verified present in Core 31.1), 0 DIFFERS, 1 CORE-ERROR
(`gettxoutproof prove_witness` — the witness-proof wire format is a
Knots extension Core doesn't implement), 53 BOTH-ERROR (identical
error paths). First matrix vs Knots: 46 MATCH, 2 EXPECTED-DIFF,
3 DIFFERS — `fullrbf` was a genuine policy divergence then; the
mempool has since been aligned to Core 29.x (below).

`estimatesmartfee` now returns Core's no-data result object
(`{"errors": ["Insufficient data or no feerate found"], "blocks": 0}`)
and its full argument-validation table (`-3` type, `-8` range,
case-insensitive `estimate_mode`). The historical CORE-ERROR on
`getrawtransaction` was a flag asymmetry (reference ran without
`-txindex`); the Core 29.4 reference runs with it, so that row is now
matched — only `in_active_chain` (added upstream after 29.4) remains
expected-different. `sendrawtransaction` error
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
(incl. `networkhashps` computed through 256-bit chainwork division,
`currentblockweight`/`currentblocktx` from a live template build;
Core dropped `currentblocksize`, we match Core),
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
- `getmempoolinfo`: Knots-specific policy knobs only (`rbf_policy`,
  `truc_policy`, `dustdynamic`, `dustrelayfee*`) — correctly absent.
  The pool now carries a serialized-bytes cap (`DEFAULT_MAX_BYTES` =
  Core's 300 MB `-maxmempool` default, enforced alongside the entry
  cap via evict-lowest-feerate) and reports `maxmempool`; both relay
  floors are the 29.x relaxed 100 sat/kvB (0.1 sat/vB) defaults and
  `fullrbf` matches deployed Core — replacements no longer require
  BIP125 signaling, only the fee-bump economics.

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
- `getnettotals` reports cumulative wire bytes across *all* sessions
  — `PeerManager` now absorbs each closed session's telemetry into
  `closed_bytes_*` on every removal path (evict, dead, disconnect),
  so a dropped peer's traffic doesn't vanish. `uploadtarget` reports
  the unlimited (`-maxuploadtarget=0`) shape since no cycle budget is
  enforced.
- `getnodeaddresses`/`addpeeraddress` landed with Core's full
  `GetNetClass`/`IsRoutable` model: the addrbook now keys entries by
  (ip, port) like `CAddress::GetKey`, unions services on re-gossip
  (`nServices |=`), and — the behavioral change — **rejects unroutable
  addresses entirely**, matching `AddrManImpl::AddSingle`'s
  `!IsRoutable()` gate. Gossip of loopback/private/doc-range addresses
  no longer enters the book (Knots' regtest book is empty for the same
  reason), and `load` drops stale unroutable rows from older
  `peers.dat` files. `fc00::/7` classifies as unroutable because
  `MaybeFlipIPv6toCJDNS` only flips when `-cjdnsreachable` is set —
  verified live: `addpeeraddress "fc00::1"` is `failed-adding-to-new`
  on both daemons, while `2002::1` (6to4 linked-v4) stores and reports
  `network:"ipv4"`. Onion/I2P inputs return `{"success":false}` — our
  16-byte `NetAddr` can't represent them.
- `getdeploymentinfo` implements Core's `versionbits.cpp`
  state machine (`crates/avila-consensus/src/bip9.rs`): state is
  evaluated against `pindexPrev` aligned to the last block of its
  completed confirmation period, transitions replay one window at a
  time, DEFINED checks the timeout *before* the start time, STARTED
  checks timeout *before* counting (a window that reaches threshold
  on the deadline still fails), and LOCKED_IN→ACTIVE waits for
  `min_activation_height`. Per-network `Params` carry Core's
  `vDeployments` table — mainnet taproot (bit 2, start 1619222400,
  timeout 1628640000, min-activation 709632), regtest testdummy
  (bit 28, start 0, NO_TIMEOUT, threshold 108/144), and the
  ALWAYS_ACTIVE/NEVER_ACTIVE sentinels. Live-verified past the first
  regtest window: `status:"started"`, `since:144`, `statistics`
  `{period:144, elapsed:6, count:6, threshold:108, possible:true}`,
  `signalling:"######"` — byte-identical to Core. (Knots emits an
  extra `period_start` in `statistics`; Core 29.4 and 31.1 don't —
  Knots-ism, not emitted.) The same machine drives `getblocktemplate`'s
  `vbavailable` and `ComputeBlockVersion` (template version
  `0x30000000` once testdummy is started, matching both).
- `gettxoutproof`/`verifytxoutproof` implement BIP37 partial merkle
  proofs (`PartialMerkleTree` in `merkle.rs`, a faithful port of
  `CPartialMerkleTree`) plus Knots' witness-aware extension: the
  `prove_witness` option emits the `version ‖ header ‖ txid-tree ‖
  gentx ‖ tail` wire form where `version` is `-1` (no witness
  commitment → `m_prove_gentx` bool tail) or `-2` (commitment → wtxid
  partial tree with a null gentx leaf). Verification reproduces
  Knots' full contract: gentx must be match 0 and a coinbase, the
  witness commitment is recomputed as `sha256d(wtxid_root ‖
  reserved)`, a null wtxid match at index 0 reports the gentx txid,
  and proofs for headers off the active chain raise `-5` "Block not
  found in chain". Live-verified byte-identical for classic and
  witness proofs on 1-tx and 2-tx blocks (the 2-tx block exercises
  the real `-2` wtxid tree), including the no-blockhash UTXO lookup,
  every error path, mode mismatches, and tampered/truncated proofs.
  Decoding caps allocation at what the input can contain — a
  CompactSize count is never trusted for `with_capacity`.

### Known semantic differences

- `getindexinfo`/`getrawtransaction` differences are flag-driven:
  `in_active_chain` is an upstream addition after 29.4 (present in
  Core 31.1, absent in 29.4) — version drift, not a Knots-ism; and
  bare-txid lookup needs `-txindex` on the reference side too.
- `getrawtransaction` without a named block now goes through the
  `-txindex` index when enabled (`run --txindex`); without it the
  error is Core's exact `-5` ("No such mempool transaction. Use
  -txindex or provide a block hash …"). Index hits report
  `in_active_chain` and active-only `confirmations` like Core.
- Mutating methods are `stop`, `sendrawtransaction`, `submitblock`,
  `submitheader`, `generatetoaddress`, `generateblock` — the pool
  admission, block connect, and tip-announce paths are all live.

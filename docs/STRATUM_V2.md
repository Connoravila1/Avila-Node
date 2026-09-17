# Stratum V2 investigation

Roadmap item: "investigate compatible Stratum V2 job declaration and
template-provider integration" (W9).

## What Stratum V2 asks of a full node

Stratum V2 splits mining traffic into three sub-protocols:

| Protocol | Direction | Purpose |
| --- | --- | --- |
| Template Provider (TP) | node → proxy | `NewTemplate`, `SetNewPrevHash`, `RequestTransactionData` (+ `-WithSuccess`) |
| Job Declaration (JD) | miner ↔ proxy/pool | miners declare their own templates (`DeclareMiningJob`, `ProvideMissingTransactions`) |
| Mining | miner ↔ proxy/pool | share accounting (`SubmitShares*`, `NewMiningJob`, `SetTarget`) |

A full node's natural role is **Template Provider**: it serves valid
templates to a downstream Job Declarator or proxy which handles miner
connections and share accounting. A node does not run the Mining
protocol itself — share accounting, payouts, and per-miner channels
belong to the pool layer. Solo miners pair a Job Declarator (usually
bundled in `minerd`/`jd-client` style tooling) against the node's TP
socket.

## State of this codebase

`Mempool::build_template` already produces consensus-valid templates:
ancestor-feerate package selection, BIP34 coinbase, BIP141 witness
commitment, MAX_BLOCK_WEIGHT bound. The missing pieces for a TP
surface:

- **Framing** — Sv2 frames are 6-byte headers (`extension`,
  `msg_type`, `msg_length`) optionally inside a Noise `NX` handshake
  over TCP. Plaintext framing is legal for solo mining on loopback.
- **Message set** — TP needs: `SetupConnection`, `CoinbaseOutputDataSize`,
  `NewTemplate`, `SetNewPrevHash`, `RequestTransactionData`,
  `SubmitSolution`. ~8 message types total.
- **Refresh policy** — templates are pushed on tip change and mempool
  churn; the existing sync-loop tick and electrum notification pump
  already observe both, so a TP emitter can subscribe the same way.

## Interoperability evidence

Bitcoin Core 28+ ships an equivalent surface via `-sv2`
(`libmultiprocess` template provider) — the reference implementation
for TP semantics. `RequestTransactionData` exists because the proxy
builds coinbase-less templates from hashes; a first implementation can
serve `RequestTransactionData` by looking the txids up in the mempool
and chainstate, both already indexed here.

## Decision

Implement the **Template Provider** role (plaintext framing first,
Noise `NX` as a follow-up): it is the minimum surface for solo mining
and the same code path a proxy integration would use. The Job
Declaration and Mining protocols stay out of scope for the node —
they are pool/proxy responsibilities, matching Core's own split
(`-sv2` on bitcoind serves TP only).

Remaining work for a full implementation:

1. Sv2 frame codec + `SetupConnection` negotiation.
2. TP message encoders/decoders (`NewTemplate` carries the serialized
   tx list + coinbase-outputs allowance; `SetNewPrevHash` flushes on
   every tip change).
3. A `--sv2tp <addr>` listener wired like `--electrum`, emitting on
   template refresh.
4. `SubmitSolution` → `submitblock`-equivalent admission path
   (existing `ProcessNewBlock` equivalent already validates full
   blocks).
5. Optional Noise `NX` encryption for non-loopback deployments.

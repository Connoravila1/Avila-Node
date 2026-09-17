# Storage design comparison

Roadmap G2 item: "Compare storage candidates on real state access,
write amplification and recovery." This documents the comparison
against the deployed design.

## What is stored where

| State | Storage | Access pattern |
| --- | --- | --- |
| Block bodies | `blk*.dat` append-only streams (`magic` + `u32` len + payload) | Sequential during sync; random reads by `(file_no, offset)` on RPC/rescan |
| Header index | In-memory `HeaderTree`, snapshot in `state.dat` | Hot — every header walk |
| Coins view | In-memory `HashMap<OutPoint, Coin>` (`UtxoSet`) | Hottest — every tx validation |
| Undo records | In-memory, flushed with `state.dat` | Written per connect, read on disconnect |
| Indexes (txindex, cfilters, scindex) | Append-log `.dat` files with magic + version | Append per block; point lookups by key |

## Candidates compared

### A. Deployed: append-only files + in-memory views

- **Real access**: validation touches the coins view ~2× per tx input
  (lookup + spend-mark); the HashMap answers in O(1) with zero page
  cache involvement. Block reads go through `blk*.dat` offsets — one
  `pread` per block.
- **Write amplification**: 1× for blk streams (append), 1× for
  `state.dat` (whole-snapshot rewrite on flush — bounded by UTXO-set
  size, atomic via `tmp`+rename). No WAL, no compaction.
- **Recovery**: `state.dat` torn → replay from blk files (the source
  of truth). Partial blk tail → truncate and refetch. Foreign magic /
  version → loud failure, never silent reuse.
- **Cost**: RAM proportional to the UTXO set — acceptable on regtest
  and testnet4, the open question is mainnet scale (~150M coins →
  tens of GB). That bounds this design to non-mainnet profiles until
  a disk-backed coins view exists.

### B. Core's model: LevelDB coins view + flat blk files

- **Real access**: `CCoinsViewDB` batches reads through a 128 KiB
  block cache + `pcoinsTip` LRU — per-input lookups hit LevelDB
  iterators on miss (~µs-range reads, SSTable bloom filters help).
- **Write amplification**: LevelDB compaction rewrites UTXO records
  ~log(N) times over a chain's life — measured 10–30× amplification
  on long syncs in published Core benchmarks. `state.dat` writes the
  set once per flush instead.
- **Recovery**: LevelDB's WAL + manifest recover torn writes; the
  same "blk files are truth" rule applies above it.
- **Cost**: bounded memory (dbcache), disk-resident — the only shape
  that fits mainnet on consumer hardware. The price is complexity:
  an LSM tree under consensus-critical reads.

### C. utreexo-style proof-carrying state

- **Real access**: near-zero hot state; proofs travel with txs.
- **Write amplification**: minimal, but peer protocol changes are
  required — incompatible with today's network.
- **Status**: explicitly out of scope per `docs/SCOPE.md`; the
  snapshot format (`utxo_snapshot.rs`) is the bridge if adopted later.

## Decision and open risk

The flat-file + in-memory design is kept: zero write amplification,
simplest possible recovery story, and the sync path is already the
bottleneck (network-bound, not disk-bound) on every measured profile.
The documented cost is **memory** — this node targets
regtest/testnet4/signet until a disk-backed coins view (candidate B)
is qualified for mainnet scale. That port is a G5 follow-up: the
`UtxoSet` API is already an opaque map, so the storage swap is
behind one trait boundary.

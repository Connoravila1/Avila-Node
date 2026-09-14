# Node landscape survey

**Survey date: 2026-09-14.** This is the comparison field for
[docs/SCORECARD.md](SCORECARD.md): every row in the scorecard names its
reference implementation here, with inclusion criteria and exclusion reasons.
Status claims below are as of the survey date and are not re-verified
continuously; re-check when a row actually runs.

## Scope and criteria

Included: software that performs *full consensus validation* of the Bitcoin
chain (any storage/assumption model counts, but different guarantees get
separate scorecard rows), or a specialist service that is the strongest
available reference for a scorecard dimension. Excluded: SPV-only clients,
altcoin forks, dead projects (noted once, then dropped), wallets that consume
a node rather than being one.

## Full validating nodes

| Implementation | Lang | Status (survey date) | Validation/storage model | Distinctive properties |
| --- | --- | --- | --- | --- |
| **Bitcoin Core 31.1** | C++ | Latest release (2026-07-08); >95% of reachable network | Archival or pruned; assumevalid (script checks skipped below a hardcoded height), headers-first IBD | The de facto spec. Cluster mempool work in flight; libbitcoinkernel extracted for reuse; Guix reproducible releases; `-blockfilterindex`, mining RPC. The reference for nearly every row. |
| **Bitcoin Knots 29.3** (`.knots20260508`) | C++ | Active; Core 29.3 base | Identical consensus | Policy-divergence laboratory: configurable `datacarrier*`, `rejecttokens`, `rejectparasites`, ephemeral-anchor and bare-pubkey policy, `spkreuse`, `-maxtxlegacysigops`, RAM-aware `dbcache`, retained legacy wallet, NAT-PMP. Ships an optional **BIP-110/RDTS** build — a *consensus* divergence gated on miner signaling; if it ever activates it is a network rules change, otherwise it is a policy+signaling curiosity. Proof that policy ≠ consensus in practice. |
| **btcd v0.26** | Go | Active; in production since 2013 | Archival or pruned (v0.26 added `--prune`) | Clean-room modular Go packages (wire/tx/script/utxo separable) — the model our crate boundaries emulate. v0.26 claims IBD ~45 h → ~6 h and `testmempoolaccept`. Had security-critical UTXO/reorg cache bugs in the v0.25 era — a reminder that independent implementations pay a correctness tax; mitigated for us by the differential adapter. No built-in wallet (btcwallet). |
| **Gocoin** | Go | Active | Archival; **whole UTXO set in RAM** | The maximal-speed design point: custom non-GC UTXO memory module, published sync charts vs Core 30.2 (Hetzner i7-7700/64 GB), `LastTrustedBlock` sync speedup, optional `libsecp256k1` acceleration. The opposite end of the memory axis from Floresta — useful as the RAM-spend reference for P1/P3. |
| **Floresta v0.9.0** | Rust | Active; self-described experimental | **Utreexo accumulator** — UTXO set is a small commitment; pruned-only (<1 GB); PoW fraud proofs | The proof-assisted design point: BIP-183 Utreexo messaging, script validation via `libbitcoinkernel` (shared C++ validation code — a hybrid, not an independent engine; claims ~15× over libbitcoinconsensus), watch-only wallet + Electrum server, Core RPC-compat test rig. Different guarantees → separate scorecard rows where the UTXO model changes the check set. |
| **libbitcoin v4** (node/server/explorer) | C++ | Active | Archival; async, high-performance focus | Modular toolkit; ZeroMQ/CurveZMQ query API with identity certs. **AGPL-licensed** — usable as a benchmark reference, not for code reuse. |
| **BitcoinJ** | Java | Active | **SPV only — not a full node** | Excluded from validation rows; relevant only as a client/consumer contrast. |
| **bcoin** | JS | Unmaintained | — | Dead; the 2018 inflation bug is a cautionary tale for minority implementations. Excluded. |
| **Parity Bitcoin** | Rust | Dead since ~2019 | — | Excluded (unmaintained). |

## Specialist services (row-level references)

| Service | Reference for | Notes |
| --- | --- | --- |
| **Fulcrum / electrs / ElectrumX** | P7 wallet/index query latency | Electrum-protocol servers; Fulcrum claims the performance lead. These sit *on top of* a node — comparisons must load identical index state. |
| **mempool.space (esplora backend)** | P7 + observability | What a public block-explorer pipeline looks like as a service workload. |
| **Core `-blockfilterindex` / btcd filter serving** | P7/P5 (BIP157/158) | Compact-filter serving cost and query latency. |
| **Stratum v2 reference implementation** | P9 mining | SRI is Rust; `getblocktemplate`-equivalent work plus translator/proxy roles — the modern mining interface to match. |
| **utreexod** | P4/proof-assist | Go Utreexo daemon; alternative proof-service deployment shape to Floresta's embedded model. |

## Scorecard row → reference mapping

| Row | Primary reference | Secondary / notes |
| --- | --- | --- |
| C1 correctness | **Bitcoin Core** (pinned release; functional-test corpus, `submitheader` adapter) | rust-bitcoin dev-differential; Knots consensus-identical until RDTS |
| P1 initial validation | **Core 31.1** | Gocoin (RAM-resident extreme); Floresta/Utreexo in a *separate* row (different check set via proofs) |
| P2 tip/reorg latency | **Core** | btcd for a second independent implementation |
| P3 memory | **Core** | Gocoin (max-RAM) and Floresta (min-RAM) as the axis ends |
| P4 storage | **Core** (LevelDB chainstate) | Floresta (<1 GB utreexo); libbitcoin (custom db engine) |
| P5 network | **Core** (incl. Erlay status at run time) | btcd (BIP155); Knots for policy-visible traffic differences |
| P6 energy | **Core** | Floresta as the low-power reference |
| P7 services | Fulcrum / electrs / esplora | vs. our future index services at matched coverage |
| P8 mempool | **Core** | **Knots** — the richest policy knob set for adversarial/policy cases |
| P9 mining | **Core `getblocktemplate`** | Stratum v2 SRI for the template/distribution layer |
| Q1 privacy | **Core** (Tor/I2P/CJDNS) | Knots policy-level filters as observable-behavior contrast |
| Q6 supply chain | **Core** (Guix reproducible builds) | btcd's reproducible-build verification process |

## What we take vs. deliberately differ on

Adopt where proven (engineering, not verdicts): headers-first sync, BIP324 v2
transport, `-blockfilterindex`-style serving, Core's functional-test corpus as
an adversarial input source, Guix-style reproducible releases, cluster-mempool
ordering concepts, the general direction of Utreexo/assumeutxo as *optional
profiles* rather than the base model.

Deliberately differ:

- **Storage** — no LevelDB-bolted-on CoinsView clone; the UTXO/block/index
  layout is designed for our query and recovery patterns, decided only after
  measured baselines (P4 row).
- **UTXO-set memory** — not RAM-resident-by-default like Gocoin; a bounded
  cache over durable state, with a documented high-RAM profile if it wins.
- **Mempool** — cluster-aware admission/eviction from the start, not a
  migration; policy knobs exposed deliberately rather than accreted.
- **Validation engine** — first-party Rust (recorded decision in
  ARCHITECTURE.md); Floresta's `libbitcoinkernel` link is the rejected
  alternative.
- **Observability** — bounded structured events and typed interfaces instead
  of `debug.log` archaeology and bolted-on indexers.
- **Policy surface** — Knots proves policy configurability is where
  implementations legitimately differentiate; ours should be explicit,
  documented and safe-by-default rather than inherited defaults.

## Re-survey triggers

Re-check this table when: a scorecard row actually runs (pin exact revisions
then), a referenced project ships a validation-model change (e.g. assumeutxo
in a Core release, Utreexo in Core, an RDTS activation), or a new serious
implementation appears.

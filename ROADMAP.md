# Roadmap

Build a complete, publicly usable Bitcoin node and pursue leadership across every
important dimension of node operation. Core compatibility and lightweight operation
are foundations to exceed, not the ceiling. The ambition includes expert headless
use, a capable egui desktop, constrained devices, wallet infrastructure and mining.

This roadmap has two parts: **integration gates** that establish a working node,
and **engineering and research workstreams** that pursue advantages throughout
development. Research starts as soon as its prerequisites exist. It is not a final
miscellaneous milestone after feature parity.

The [scorecard](docs/SCORECARD.md) defines workloads, operating profiles, stretch
targets, comparison rules and evidence. All node-performance results are currently
**unmeasured**. Milestones are acceptance gates, not calendar promises or claims
that unresolved research will succeed.

## Integration gates

### G0 — Application foundation (current)

- [x] Public-use project under Connor Avila's GitHub account, independent of Avila Labs; MIT license.
- [x] Rust workspace, pure shared contracts, CLI and native egui shell.
- [x] Strict configuration parsing, separate network data paths, bounded local events.
- [x] Explicit capability inspection and startup refusal for absent node subsystems.
- [x] Committed dependencies and CI for formatting, linting, tests, docs and CLI smoke checks.
- [x] Supplied branding, searchable/resizable tables, keyboard navigation, egui development tools.
- [x] Light, Dark and true Black appearance with remembered theme and scale.
- [x] Full-node scope, egui capability plan and measurement requirements.
- [ ] Native packaging and interaction validation across intended desktop platforms.

Evidence: workspace checks and application interaction tests pass. Unknown chain
measurements remain unknown. This gate establishes an application, not a Bitcoin node.

### G1 — Consensus fixtures, reference adapter and measurement harness

- [x] Record the validation-engine decision, trusted dependencies and extraction boundaries.
  See docs/ARCHITECTURE.md "Validation-engine decision".
- [x] Implement bounded decoding, transaction/witness identities, headers, target arithmetic,
  proof of work, linkage, chainwork and explicit network parameters.
- [x] Inventory historical and activated consensus rules with valid/invalid fixtures,
  activation context and provenance; start mainnet cases immediately.
  See docs/RULE_INVENTORY.md and fixtures/manifest.json.
- [x] Add a pinned Core reference adapter, parser/arithmetic fuzzing and disagreement artifacts.
  See tools/check_headers_core.py (adapter + per-run reference pin and artifact)
  and fuzz/ (libFuzzer targets).
- [x] Implement the scorecard runner: exact manifests, raw measurements, correctness checks,
  cold/warm workloads and reproducible reference runs.
  See tools/scorecard_headers.py and tools/scorecard_blocks.py (segment replay);
  artifacts land in target/scorecard/.
- [x] Record baseline measurements before selecting hot-path layouts or storage defaults.
  Header-acceptance baseline: experiments/2026-09-header-acceptance-baseline.md;
  block-replay baselines: target/scorecard/blocks-*.json.

Evidence: implemented checks are enumerated, invalid cases fail for the expected
reason, reference discrepancies have reproducible cases, and another developer can
repeat measurements. Header validation alone is not labeled full validation.
Workstreams W1–W4 begin here; security/privacy threat models begin with the interfaces.

### G2 — Offline full validation and durable chainstate

- [x] Implement Script and contextual transaction/block rules, UTXO transitions,
  historical activation behavior, competing chains and deterministic fork selection.
- [x] Support offline block import, atomic commits, undo, reorgs and resumable replay.
- [ ] Compare storage candidates on real state access, write amplification and recovery.
- [x] Separate active tip, complete validation coverage, index coverage and assumptions.
- [x] Validate historical mainnet data and adversarial fixtures, including connect,
  disconnect and reconnect under interrupted writes, disk exhaustion and corruption.

Evidence: reproducible accept/reject and state comparisons, correct reorg behavior,
recoverable commits and a published initial full-validation performance profile.
Storage and synchronization research can use this implementation before P2P is ready.

### G3 — Independent network synchronization

- [x] Bounded wire framing and message codecs (`avila-p2p::codec`,
      `avila-p2p::message`): 4 MiB `MAX_PROTOCOL_MESSAGE_LENGTH`, checksum
      verification before delivery, network-magic and command-field
      validation, and the sync-relevant command set (`version`/`verack`,
      `ping`/`pong`, `sendheaders`/`wtxidrelay`/`sendaddrv2`/`feefilter`,
      `getheaders`/`headers`, `inv`/`getdata`/`notfound`, `block`/`tx`,
      `getaddr`/`addr`/`addrv2`, `mempool`, `reject`).
- [x] Per-peer session state machine (`avila-p2p::session`): Core's
      `version`/`verack` choreography, handshake timeout, session-layer
      `ping`→`pong`, per-peer send budget, pre-version drop and
      post-verack negotiation disconnect.
- [x] Headers-first acquisition (`avila-p2p::sync` + `HeaderTree::locator`):
      `getheaders` paging capped at `MAX_HEADERS_RESULTS`, `inv`→`getdata`
      with `MAX_BLOCKS_IN_TRANSIT_PER_PEER` and `BLOCK_STALLING_TIMEOUT`,
      witness-aware block requests, and consensus-validated intake.
      Proven live: `examples/peer_probe` completed a real handshake and a
      120-block headers-first sync against a Bitcoin Knots v29.3 regtest
      peer, validating every block through `Chainstate`.
- [x] Peer discovery and lifecycle: `avila-p2p::addrman` (bounded,
      recency-ordered gossip table with tried/attempt marks) feeds
      `avila-p2p::manager` (`PeerManager` — a bounded multi-peer set
      driving session+sync pairs over one `Chainstate`). `getaddr` is
      served from the book, `addr`/`addrv2` gossip is ingested, DNS-seed
      bootstrap resolves `vSeeds` per network, and `tick_net` redials
      from the book on disconnect. The book persists as `peers.dat`
      (versioned, sha256d-checksummed, atomic) under the sync data dir —
      restarts keep learned candidates; a corrupt file costs only
      gossip history. Proven live: `examples/mainnet_probe`
      resolved 291 mainnet candidates, dialed four real Core/Knots
      peers, and validated 4000 mainnet headers — including the h2016
      retarget — through `Chainstate`.
- [x] Multi-peer download scheduling and restart/resume: the per-tick
      fill pass hands each established peer `getdata` for
      indexed-but-unfetched blocks, skipping hashes reserved by any peer
      — no duplicate fetches, and a stalling/disconnecting peer's
      reservations release automatically so its blocks are reassigned
      next tick. Proven live: two Knots regtest peers fed one chainstate
      to h120 with zero duplicate requests. Connected tips are relayed
      to the rest of the peer set — `headers` for peers that sent
      `sendheaders`, `inv` otherwise — mirroring Core's
      `NewPoWValidBlock` announce (the delivering peer is excluded).
- [x] Global budgets, eviction scoring, and cancellation: a shared
      aggregate in-flight budget (`MAX_BLOCKS_IN_TRANSIT_TOTAL`,
      overridable) bounds block reservations across the whole peer set —
      fill-pass, headers-`fetchable`, and `inv`-driven fetches all draw
      it down. Inbound admission on a full set evicts the least
      recently useful inbound peer (usefulness = delivered headers or
      blocks; the headers leader and recent suppliers are protected —
      Core's `SelectNodeToEvict` shape); outbound peers are never
      evicted for inbound slots. Cancellation is implicit: a stalled or
      evicted peer's reservations release and the fill pass reassigns
      them next tick.
- [x] Exercised on all four networks: regtest (full sync + serve, both
      directions against Knots), and live mainnet / signet / testnet4
      runs via `examples/mainnet_probe` — DNS-seeded discovery, real
      handshakes, thousands of headers (retargets included) and real
      block connection through `Chainstate`, signet blocks passing
      BIP325 challenge verification.
- [x] Implement selected transport/privacy constraints together with
      traffic paths (partial): `avila-p2p::proxy` implements SOCKS5
      no-auth CONNECT for IP and domain targets (the `.onion` path),
      `PeerManager::connect_via` runs the P2P session over the proxied
      stream, and `avila-node sync --proxy` routes all dials through it
      — proven live by syncing 16 regtest blocks through a SOCKS5
      forwarder. BIP324 v2 transport remains open.
- [x] Add real sync, peer and resource observations to CLI and GUI
      (CLI side): `avila-node sync` drives `avila-node::sync::run` —
      DNS-seeded or `--connect`-specified peers, headers-first download
      through `PeerManager<TcpStream>` with live progress (headers,
      connected height, peer count, in-flight, connects/drops) and a
      final report. GUI side: `avila-gui` auto-starts sync on launch,
      shows a health verdict, live headers/connected rails, a
      recent-blocks tape, a per-peer table (claims vs. served), and
      pool/orphan/fee observations in the chain ticker.

Evidence: multi-node sync/reorg tests, malformed and stalling peers, unavailable
privacy routes, interrupted downloads and sustained synchronization all have tested
outcomes. Mainnet readiness requires independently validated history and continuing
operation. Compare complete initial download and catch-up, not only local replay.

### G4 — Complete everyday node and service workflows

- [x] Persistent operation: `avila-node run` is a real daemon —
      unbounded headers-first sync with the block store resuming
      across restarts, then continuous peer service, relay and tip
      announcements until stopped (`--connect`, `--proxy` supported).
      Control channel started: `--rpc` binds a JSON-RPC surface
      gated by a per-session `.cookie` (Core's format and 0600
      permissions, deleted on shutdown; unauthenticated requests
      get HTTP 401) and an `avila-node rpc <method> [params]`
      client reads it. Snapshot methods answer from the last
      published status (getblockcount, getbestblockhash,
      getblockchaininfo, getpeerinfo, getmempoolinfo,
      estimatesmartfee, uptime, help); the sync loop answers
      live-chainstate queries between ticks (getblockhash,
      getblockheader, getblock verbosity 0-2, getrawtransaction
      from the pool or a named block, gettxout with mempool-spend
      awareness, getchaintips, getrawmempool, getmempoolentry,
      getmempoolancestors/descendants, getorphantxs,
      testmempoolaccept with a per-gate policy trace,
      getblocktemplate built from live chainstate + pool,
      getmininginfo, getnetworkinfo, getconnectioncount, stop,
      sendrawtransaction, submitblock, submitheader,
      generatetoaddress, generateblock, savemempool,
      validateaddress, getblockstats (undo-backed fee/UTXO
      aggregates, Core's selector errors and stats filter),
      getdifficulty) — verified live over curl and the client.
      Genesis is served even though its body is never stored:
      `Params::genesis_block` reconstructs Core's per-network
      `CreateGenesisBlock` coinbase and `Chainstate::body` falls back
      to it, so `getblock 0` is byte-identical. JSON doubles serialize
      through Core's `%.16g` rule (`core_num`), reproducing UniValue's
      16-significant-digit rounding and integer-form `1`. The pool
      survives clean restarts like
      Core's mempool.dat: saved on shutdown (and via savemempool),
      re-admitted through full policy on start — entries whose inputs
      a newer tip spent are skipped, not fatal. `run --txindex`
      maintains Core's txid→block index
      (`txindex.dat` append log, resumable backfill, entries survive
      reorgs); `getrawtransaction` resolves bare txids through it and
      reports `in_active_chain`. Wallet functionality remains open.
- [x] Implement mempool admission, packages, replacement, eviction,
      relay and reorg reconciliation (first slice): `avila-mempool`
      applies consensus input/script checks identically to block
      connect (shared `check_tx_inputs`, `bip68_locks_satisfied`,
      `check_input_scripts`) plus Core's standardness set, weight cap,
      min-relay fee, BIP125 replacement (RBF signaling + fee bump), and
      bounded eviction by fee rate; unconfirmed parents resolve through
      the pool. `PeerManager` owns the pool: `tx` messages admit,
      `inv` announces to tx-relay peers (wtxid for BIP339 peers), `inv`
      announcements fetch as `MSG_WITNESS_TX`, `getdata` serves pooled
      txs, and connected blocks purge confirmed/conflicted entries.
      Orphan pool and disconnected-block reinsertion landed with it;
      ancestor/descendant package limits (Core's 25-entry / 101 kvB
      caps) are enforced at admission.
- [x] Replayable policy explanations: `Mempool::explain_tx` dry-runs
      every admission gate (context-free, resolution, BIP125 signal and
      fee, package limits, consensus inputs, BIP68, scripts, relay fee,
      capacity) and returns a per-gate trace without mutating the pool.
      Isolated shadow-policy evaluation remains open.
- [ ] Deliver versioned control, watch-only descriptors, wallet
  broadcast and scoped service access. Authentication landed:
  per-session `.cookie` (Core format, 0600, HTTP Basic, 401 without
  it, removed on shutdown) plus the `avila-node rpc` client. The
  compatibility matrix has a tested start: `tools/compare_rpc.py`
  diffs every shared field against a live Knots daemon — 39 calls
  exact-match including `decodescript` (asm, descriptor checksums,
  P2SH/segwit wraps), `gettxout`, `getblock` verbosity 2,
  `getblocktemplate` (22 fields) and `getmininginfo` (incl.
  `networkhashps` via 256-bit chainwork division). The only value
  divergence is `fullrbf` (we enforce BIP125 signaling; Knots runs
  full-RBF); presence-only gaps are documented in
  `experiments/2026-09-14-rpc-compat-matrix.md` (per-peer byte/ping
  telemetry, `localaddresses`, Knots-specific policy knobs).
  Broadcast landed: `sendrawtransaction` admits to the pool through
  the full `AcceptToMemoryPool` gate set and relays an inv to peers —
  verified end-to-end (Knots fetched and pooled our submission), with
  Core's exact error paths (`-22` decode, `-26` reason strings,
  `-25` maxfeerate/maxburnamount gates, silent success on resubmit).
  The mining loop closed with `submitblock`: a template-built block
  submitted over RPC connected to our chainstate and was announced to
  and accepted by Knots at h121; Core's status strings match
  (`null`/`duplicate`/`inconclusive`/`duplicate-invalid`, `-22` decode
  failures). `generatetoaddress`, `generateblock` and `submitheader`
  complete the mining surface — `generatetoaddress` mined h122–h124
  live to a decoded address (new base58check/bech32/bech32m decode
  direction) with Knots accepting every announced block;
  `generateblock` mines an explicit tx set (txid-in-pool or raw hex
  admitted first) to an address or descriptor (`addr`/`raw`/`pk`/
  `pkh`/`wpkh`/`tr`/`rawtr` — `tr` applies the real BIP341 tweak);
  `submitheader` matches Core's orphan and decode errors.
  Fee information started:
  `FeeEstimator` records (rate, blocks-to-confirm) samples and
  `estimatesmartfee` serves any target with data, erroring honestly
  when the sample set is empty.
- [ ] Deliver Electrum/compact-filter services with tested clients and explicit index coverage.
- [x] Pruned operation (first slice): `BlockStore::prune_to_bytes`
      deletes the oldest blk files past a byte budget (never the tail);
      `have_body` reports pruned bodies absent so sync refetches them,
      resubmitted pruned blocks re-store on `accept_block`, and a reorg
      reaching a pruned body fails loudly at disconnect. Wired as
      `avila-node sync --prune-mb` and the GUI's prune field. Verified
      historical reacquisition for rescans remains open.
- [x] Mining templates (engine slice): `Mempool::build_template`
      greedily fills a block by fee rate respecting in-pool parent
      order and MAX_BLOCK_WEIGHT, pays subsidy+fees via a BIP34
      coinbase, and sets the BIP141 witness commitment when needed.
      Verified end-to-end: built templates pass `accept_block` and
      connect. Ancestor-feerate package mining and Stratum V2 remain
      open.
- [ ] Provide backup/restore, migration/rollback, resource presets and actionable recovery.

Evidence: documented end-to-end wallet, mining, pruning, reorg, service-isolation and
recovery tests. Headless and desktop workflows use the same commands and state.
An unsupported API or incomplete scan reports its actual status.

### G5 — Public release qualification

- [ ] Qualify supported Linux, Windows and macOS builds and selected x86-64/ARM64 hardware.
- [ ] Exercise long-running loads, network partitions, resource exhaustion and crash recovery.
- [ ] Publish scoped privacy/security evidence, independent review findings and fixes.
- [ ] Verify reproducible release builds, signed artifacts, provenance and dependency/license inventory.
- [ ] Test clean installation, upgrade, rollback and restore with documented compatibility limits.
- [ ] Validate accessibility, keyboard use, appearance, scaling and real operator tasks.
- [ ] Publish the scorecard with successes, regressions, unsupported cases and reproduction data.
- [ ] Establish security reporting, supported-release policy, contributor guidance and release ownership.

Primary-node readiness requires the combined evidence from G1–G5. Release labels
must identify qualified profiles and features. A release can be useful before every
research goal succeeds; releasing it does not mark unfinished leadership goals complete.

## Engineering and research workstreams

Each workstream remains part of the product scope. Optional means the operator can
disable its service or cost; it does not mean the project can ignore that workflow.
Each experiment records a question, entry point, baseline and integration gate.

### W1 — Consensus correctness and assurance

Begin at G1. Build a rule-to-test inventory spanning historical exceptions,
activation boundaries, malformed encodings, arithmetic, Script and chain context.
Combine independent fixtures, differential tests, property testing, fuzzing,
deterministic replay and targeted formal analysis of tractable state machines.
Investigate shadow verification with bounded overhead and independently implemented
checks where they can detect shared mistakes.

Integrate with reproducible agreement and explicit coverage; resolve discrepancies
from rules and evidence rather than majority voting. A clean test corpus cannot
prove absence of consensus bugs. Track both correctness evidence and attack costs.

### W2 — Validation speed, scheduling and energy

Begin at G1 microbenchmarks and G2 replay. Explore compact data layouts, allocation
reduction, context-correct caching, pipelined decoding and validation, bounded
parallel verification, efficient vetted cryptography and adaptive resource budgets.
Preserve deterministic commit ordering and correct cancellation/reorg behavior.
Profile cache misses, disk stalls, contention and energy per completed workload.

Target substantially faster complete verification, lower peak memory and lower
tail latency together. Integrate based on end-to-end gains across hardware and
hostile inputs; a faster isolated primitive is insufficient evidence.

### W3 — Accelerated synchronization with explicit verification

Prototype after G1 fixtures; compare against G2 full replay, then G3 network sync.
Investigate verified hints, parallel historical work and
[SwiftSync's original proposal](https://gist.github.com/RubenSomsen/a61a37d14182ccd78760e477c78133cd),
with the [archived protocol draft](https://github.com/2140-dev/swiftsync-bips) as
additional research context rather than an assumed stable specification.
Evaluate the exact algorithm and checks; different variants can have different
requirements. Record hint production, download, validation, storage and failure costs.

Develop snapshot bootstrapping with separately reported active state and background
validation, informed by [AssumeUTXO's chainstate separation](https://github.com/bitcoin/bitcoin/blob/master/doc/design/assumeutxo.md).
Measure time to usable tip and time to complete historical verification separately.
Corrupt/missing hints, snapshots and interrupted work require tested recovery.
Fewer executed checks must never be presented as faster equivalent full verification.

### W4 — Storage, compact state and low-resource operation

Begin storage experiments at G1 and integrate with G2. Compare hot/cold state
separation, cache policies, sequential writes, compression, indexes and undo formats.
Pursue low write amplification, bounded growth, fast restart, reduced wear and
explainable repair across archival, pruned and compact modes.

Prototype [Utreexo-style accumulators](https://eprint.iacr.org/2019/611), proof
verification/caching and proof-provider behavior. Smaller local state can introduce
proof traffic and helper costs; measure both. Compare with
[Floresta's reusable Rust node and wallet services](https://github.com/getfloresta/Floresta).
Qualify constrained ARM devices and slow storage, then investigate smaller/mobile
deployments with their power, background-execution and connectivity constraints.

Integrate only with reorg, restore and historical-data availability behavior defined.
Archival retention and minimum local storage are separate profiles of the same node.

### W5 — Efficient, resilient P2P and relay

Design budgets at G1 and implement with G3. Explore peer-aware acquisition,
compact-block efficiency, reduced redundant transaction announcements, adaptive
backpressure and fair scheduling. Evaluate encrypted transport, peer diversity,
eclipse resistance, partition recovery and adversarial resource asymmetry.
[BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki) is a transport
reference; transport encryption alone does not conceal network endpoints.

Integrate with interoperability and controlled-topology evidence: propagation
latency distributions, useful versus redundant bytes, CPU per rejected input,
connection churn and recovery. Count overhead across the topology as well as locally.

### W6 — Enforced privacy and service security

Start at G1 interface design, before traffic exists. Model each traffic purpose,
permission and failure route. Implement selected Tor/I2P routing, transaction-origin
privacy, fail-closed behavior, scoped authentication, service isolation and bounded,
redacted diagnostics. Include discovery/DNS, retries, wallet/index requests and
future update mechanisms in the model. Keep local operation independent of accounts
and hosted services.

Integrate with network-capture and fault-injection tests, forbidden-route checks,
permission tests and a published threat model. Explore origin-linkability under
declared adversaries; zero observed leaks in a test is not universal anonymity.
Privacy and security remain release requirements across all later workstreams.

### W7 — Mempool economics and explainable policy

Prototype dependency graphs after G1; integrate with G4. Develop bounded package
admission, replacement and eviction, cluster-aware economic evaluation, incremental
updates and consistent reorg handling. Record why a transaction was accepted,
rejected, replaced or evicted, with bounded explanation costs.

Compare shadow policies on reproducible traffic without changing live consensus
or admission. Integrate with adversarial package tests and measurements of memory,
admission/eviction latency, relay behavior and template quality. Local observations
must not be labeled a view of the entire network mempool.

### W8 — Wallet infrastructure, indexing and private discovery

Design coverage/permission contracts at G2; integrate with G4. Deliver descriptor
watch-only scanning, a documented RPC surface, Electrum, compact filters, broadcast
and fee information. Test actual wallet clients and hardware-wallet companion
workflows while keeping signing keys outside the chain daemon.

Optimize index sharing, incremental scans, multi-wallet isolation, cancellation
and historical reacquisition on pruned nodes. Investigate Silent Payments scanning
with explicit CPU and privacy budgets. Explain scan coverage, reorg invalidation
and recovery plans. Integrate with measured query/rescan performance and complete
end-to-end wallet recovery; an unsearched interval must not appear as an empty balance.

### W9 — Mining and template quality

Prototype once G2 can validate candidate blocks; integrate with G4's mempool.
Build low-latency valid templates, incremental refresh, package selection and
reorg-safe work updates. Support solo operation and investigate compatible
[Stratum V2 job declaration](https://stratumprotocol.org/specification/06-job-declaration-protocol/)
and template-provider integration.

Measure template validity, fees selected from identical transaction sets, refresh
latency and stale work under load. Compare selection quality against bounded small
instances with known optima and realistic reference workloads. Pool-side support
and traffic costs must be explicit in interoperability results.

### W10 — Resilience, recovery and operator control

Begin failure models at G1, inject storage faults at G2 and extend through G5.
Build durable transitions, corruption detection, resumable reconstruction, precise
disk/resource budgets and explainable recovery. Test abrupt termination, partial
writes, disk full, missing history, partitions, index failures and upgrade failures.
Separate reconstructible data from state that cannot simply be downloaded again.

Provide actionable diagnostics, validated backup/restore, configuration diffs and
format-aware migration/rollback. Measure recovery time, replayed work, downtime,
data correctness and operator steps. Qualify unattended operation with long soaks
and enforced resource limits; a graceful restart test is not crash qualification.

### W11 — egui, observability and everyday usability

Started at G0 and advances with each real subsystem. Use virtualized tables,
search/filter, keyboard actions, contextual explanations and accessible controls.
Add real time-series plots, latency histograms, linked inspectors, dependency and
reorg graphs, pan/zoom, bounded replay timelines and detachable viewports when their
data sources exist. Follow the [egui plan](docs/GUI.md) for relevant demo capabilities.

Provide clear resource/privacy profiles and recovery workflows, Light/Dark/Black,
scaling, reduced motion and exportable evidence. Measure frame/input latency and
idle overhead with large datasets, plus real task completion, errors and keyboard/
screen-reader access. The GUI must remain responsive during sync, scan and failure;
headless operation retains the same control and observability semantics.

### W12 — Public distribution, maintainability and reuse

Begin with G0's workspace and continue through G5. Develop documented component
APIs, useful contribution tasks, reproducible builds, portable packaging and tested
upgrade/restore paths. Track dependencies and licenses, review trust boundaries,
and make release provenance independently checkable.

Measure supported-platform coverage, reproducibility, build/resource costs and
time to diagnose and fix failures. Provide security reporting and maintenance
documentation. Publish reusable components and negative findings as well as wins;
the integrated public node remains the deliverable.

### W13 — Proof-assisted verification and further frontier research

Start a bounded rule-coverage and cost investigation after G1; integration depends
on G2's complete reference path. Explore succinct proofs, independently checkable
sync artifacts and verified parallel/distributed work. Evaluate verifier size,
prover resources, availability, cryptographic assumptions, historical rule coverage,
chain selection and reorg behavior.

[ZeroSync's public demo verifies headers and no transactions](https://zerosync.org/demo/).
A header proof is not evidence of complete transaction/state validation. Any Avila
proof mode must state exactly what it establishes and retain a conventional replay
option. Publish feasibility failures; keep successful research eligible for product
integration without promising an unresolved cryptographic result.

## Next implementation slice

The next code milestone is G1: rule/fixture inventory, bounded header decoding and
proof-of-work/chainwork checks, a pinned reference adapter, and reproducible baseline
measurements. This gives later optimization claims something concrete to improve.
Choose the first storage and historical-validation experiments from those results.

For every later slice, identify its integration gate, workstream, scorecard rows and
acceptance evidence. Use the [experiment template](experiments/TEMPLATE.md), publish
regressions, and update implemented capabilities only after the behavior exists.

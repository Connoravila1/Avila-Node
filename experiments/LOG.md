# Experiment log

Running record of every experiment tried — adopted, rejected, blocked,
or inconclusive. One line per attempt; details live in the dated docs.
A "failed" or "inconclusive" row is a result, not a gap — write it down.

| # | Date | Experiment | Hypothesis | Verdict | Key numbers | Doc |
|---|------|-----------|------------|---------|-------------|-----|
| 78 | 09-26 | Corpus-wide occurrence join (Gate 4 pt 1, repaired ×2) | Shared join + headers in corpus + one invalidity decision + supplied-state loading | **all repaired; real contiguous LINKED segment verified clean** | REVIEW_78_FOLLOWUP repairs: AVCORP03 retains 80B headers → hash+parent linkage verified (300/300 on segment, 419/419 window), check_block per block (PoW self-consistency, merkle, context-free — closes the negative-output hole), MTP in-window where ≥11 ancestors. Single `known_invalid` → both modes exit 1, no export; script failures carry block height → failing block excluded from prefix. Component flags replace `complete`. `--boundary` loads dumptxoutset via new `snapverify::for_each_coin`; Missing becomes invalidity under complete state. Exec regressions 74 checks (8 invalidity cases × both modes + boundary semantics + prefix-boundary). Segment 341808–342108: linked, 412,825 inputs verified, 0 violations everywhere; unresolved = "absent from source records". v2→v3 identical exports reconciled (consumed-boundary coins only; +28,566 inputs verified — key-set equality ≠ validation equality). Fresh 579-test log. PUSHED 695f73c+cd3cb45 (CI green both) — REVIEW_78_PUSH repairs follow: for_each_coin returns hash_serialized_3 commitment; donor pins base-hash/base-height/txoutset-hash + wrong-network/non-adjacent/dup-outpoint/height-bound rejections; --run-manifest embeds compile-time build_rev (stale binary can't claim newer checkout) + streamed file hashes + argv JSON + exit_code; base-hash pin decode fixed (was an underflow panic); exec suite 84 checks incl. pin matrix + manifest fields. Still data-blocked on authoritative starting UTXO — dumptxoutset handoff documented. | [window-join](2026-09-26-ibd-window-join.md) |
| 77 | 09-26 | Exact state closure — occurrence-record engine vs `connect_block` (Gate 3) | Occurrence-aware batch state evaluation reproduces the real connect pipeline exactly, not just key-set | **25/25 byte-exact, verdict- AND expectation-equal** | Repaired per REVIEW_77: checked header-tree growth on both paths (frozen-MTP defect fixed), declared expected outcome+tip per case, per-block-boundary digests, rejection-preserves-state, isolated predicates (time-type BIP68, MTP locktime, fee-claim ±1, missing input, BIP30 dup-creation on synthetic bip34-off params — caught a real coinbase-skip hole). Canonical exports preserved. Scope: bounded regtest OP_TRUE chains; sigops/scripts/mainnet history excluded per audit. | [state-closure](2026-09-26-ibd-state-closure.md) |
| 76 | 09-26 | Resolver repair + executed calibration (#41/#72 gates) | File-identity, coinbase sources, per-item preimage model, executed counters | **repairs verified; matched calibration done** | V2 corpus: 599,840 resolved (89.29%), 0 txid mismatches, 0 immature; executed 517,819 (77.08%). Executed: 526,534 ECDSA attempts → 526,528 backend calls (6 parse early-returns); sighash 1.4% of 1-worker check-stage. MATCHED-subset calibration: identical selection digest both sides; structural DER items over the identical executed set 524,092 vs 526,534 helper attempts = 0.9954. 0 non-DER-shaped attempts; +2,442 excess over structural DER items is consistent with repeated signature checks, including multisig retries (classifier checks outer shape, not opcode/strict DER). Replay rejects immature corpora (exit≠0), 0-worker fails. Census: 83/83 segwit merkle verified post-fix. | [corpus-replay](2026-09-26-ibd-corpus-replay.md) |
| 75 | 09-26 | Exact-state anti-join (#42) bounded | UTXO state derivable as batch set-join over sequential ledgers | **ledger volumes only; exact-state gate open** | Span h~337–342k: 7.24M created/6.66M spent set keys (614 MB ledger writes). 77.2% created∩spent set overlap (not an exact-state proof); 16% of spends have source absent from selected records; 22.8% key-set survivor tail. Multiplicity/order/maturity/BIP30 not implemented; survivors lack full output data. | [state-join](2026-09-26-ibd-state-join.md) |
| 74 | 09-26 | Corpus-parallel script replay (#41) | Prevouts from raw corpus + parallel check_input_scripts scales sig-plane without UTXO store | **holds on resolved subset; 0 failures** | Window h340787–342234 (449 blk). Executed 515,779/671,771 inputs = **76.8%** (89.1% was per-input resolution incl. excluded-tx inputs). 10.8k→49.3k inputs/s at 1→8 workers (shared host). Zero failures authenticate scriptPubKey only — legacy sighash does not commit amounts. File-identity defect found+fixed in v2 re-run (#76). | [corpus-replay](2026-09-26-ibd-corpus-replay.md) |
| 73 | 09-26 | SHRD replacement in field u128_rshift | Gracemont SHRD cost makes >>52 extraction a real verify fraction | **small keepable win** | 404→102 SHRDs (8→1 per fe_mul/sqr kernel), 2048-trace verdicts identical. Recomputed medians: compressed+verify −5.37%, preparsed −3.22% (2/6 paired runs regress slightly). batch_y33 advice path 40.265µs/sig on 4,096 synthetic records (batch param 8192 not a real 8192 batch; producer ~91.4µs/record not included). | [shrd-replacement](2026-09-26-ibd-shrd-replacement.md) |
| 72 | 09-26 | IBD workload census (structural) | Era-resolved structural counts can replace assumed corpus parameters | **structural counts valid; hash figures were coarse estimates (regenerated in #76)** | Windows over real corpora: pre-segwit 229–408k + taproot 956.5k + genesis fixture. Per-block: 303–1,147 tx / 731–3,971 sig-items pre-segwit; 4,765 tx / 7,667 sig-items at 956k (schnorr ~8%). DER-attempt estimate matches executed within 0.46% on the matched executed subset (#76). Legacy sighash dominates hash plane — v1 amplification figure (~35–75×) retired; corrected ~3.75× lower (still dominant). | [workload-census](2026-09-26-ibd-workload-census.md) |
| 71 | 09-26 | IBD arithmetic census and hardware limits | Instruction accounting can replace unsupported universal IBD-floor estimates | **measured narrow scope; full-IBD floor unestablished** | 512 canonical mainnet ECDSA attempts: all verdicts matched, 985 field multiplies + 973 squares + one scalar inversion/attempt, no variable field inversion; compressed parse adds 14 multiplies + 255 squares. Shared-host timing ~100–135 microseconds/attempt; native compiler gain inconclusive. Static field kernels retain costly SHRD candidates. Further experiments assigned to SWE-2 | [hardware-floor](2026-09-26-ibd-hardware-floor.md) |
| 1 | 09-14 | RPC compat matrix vs Core 29.4 | RPC surface can be made byte-compatible | **adopted** | 75 calls exact-match | [rpc-compat-matrix](2026-09-14-rpc-compat-matrix.md) |
| 2 | ~09-20 | Header acceptance baseline | Header-chain parity is provable offline | **adopted** | `check_headers_core.py` 0 mismatches | [header-acceptance](2026-09-header-acceptance-baseline.md) |
| 3 | 09-22 | coinsdb snapshot ingest | redb can absorb AssumeUTXO-scale writes | **adopted w/ caveat** | 20M sorted OK; random ingest collapses ~40M | [snapshot-ingest](2026-09-22-coinsdb-snapshot-ingest.md) |
| 4 | 09-23 | Compact coin codec (Core `Coin` format) | Core's codec halves record size at scale | **adopted** | 2.0→1.0 GiB at 5M; +12–25% bulk | [coinsdb-layout](2026-09-23-coinsdb-layout.md) |
| 5 | 09-23 | Sorted-key commits | Sorting dirty map removes B-tree churn | **adopted** | +20–25% bulk commits | same doc |
| 6 | 09-23 | redb cache knob | Cache size is a real profile dial | **adopted (as knob)** | 32M cache doubles full-scan cost; reads unaffected | same doc |
| 7 | 09-23 | redb page size | Page size tunable | **rejected — impossible** | redb pins 4 KiB in file format | same doc |
| 8 | 09-23 | Hash-indexed coins engine | UTXO set has no range queries; O(1) probe beats O(log n) tree | **adopted (opt-in)** | 40M: 2.0× ingest, 2.5× reads, 5.3× commits, −44% disk; loses below ~1M | [hash-engine](2026-09-23-coinsdb-hash-engine.md) |
| 9 | 09-23 | mmap index reads (hashstore) | mmap kills the 2-syscall probe cost | **blocked — unsafe forbid** | workspace `-F unsafe-code`; page-cache fallback instead | same doc |
| 10 | 09-23 | Windowed bulk scans | 1 MiB read windows for iter/rehash | **failed — bug caught** | `1 MiB % 48 ≠ 0` misaligned every slot past 1 MiB; fixed to whole-slot windows | same doc |

| 11 | 09-23 | Real-disk 40M ingest | tmpfs numbers should hold on NVMe | **partial — caveat was real** | hash 1.9× ingest / 2.8× commits / −44% disk hold, but cold reads lose 0.4× (append-log scatters placement → no locality) | [hash-engine](2026-09-23-coinsdb-hash-engine.md) |

| 12 | 09-23 | Slot-order log compaction | Clustered placement restores cold-read locality | **partial — bar not met** | 15.8k→22.6k/s (+43%) post-compact; still 2× behind redb 46k/s. Placement helps, per-lookup page touches dominate | [hash-engine](2026-09-23-coinsdb-hash-engine.md) |

| 13 | 09-23 | Net-effect writes: tombstone elision | Same-epoch create+spend tombstones are pure waste | **adopted** | −22–25% backend ops; 501-block diff PASS | [net-effect](2026-09-23-net-effect-writes.md) |
| 16 | 09-23 | Crash fault-injection on hash engine | Commit ordering survives torn writes | **2 findings, both fixed** | torn records decoded to wrong-but-valid coins (silent corruption) → +4B keyed record tag, tears now misses; coins-ahead-of-tip tear invisible → index-header watermark, open errors loudly. File-level sim; compact() still unsafe | [fault-inject](2026-09-23-fault-injection.md) |


| 62 | 09-24 | Recon-diff divergence alarm | Does the censorship signal separate from normal sync lag? | **adopted — queue #19 closed** | `ReconRound::close` now returns both diff directions — our misses AND `their_misses` (ids we hold that their pool lacked, previously decoded-then-discarded). Alarm: edge-triggered `NetEvent::ReconDivergence` at ≥10 rounds, ≥100 their-misses, ≥4:1 dominance over our misses — wide-but-balanced diffs (slow sync) don't fire. `recon_their_misses` in getpeerinfo; `recon_divergence` events in getevents + stderr log. Test proves edge-trigger, below-threshold silence both ways. | — |
| 70 | 09-24 | Benchmark methodology + downgrade telemetry | Can claims be pinned to a real baseline? | **adopted** | `docs/BENCHMARKS.md`: Core 31.1 is the reference baseline, signet fixture is canonical, three claim tiers (mechanism / fixture-measured / comparative — only the last may say *better*). No comparative Core run exists yet — recorded honestly. `v2_downgraded` event: a v2-attempt dial landing v1 is now observable (forced-downgrade signal); `getvalidationreport` gains an explicit `coverage` block — fully_verified / pending_replay / snapshot_assumed in plain words (astra's acceptance criterion). | [benchmarks](../docs/BENCHMARKS.md) |
| 69 | 09-24 | Privacy failure matrix | Does the private-mode guarantee survive every path? | **adopted — one real leak found + closed** | `docs/PRIVACY_MATRIX.md` publishes the complete outbound surface (dials, retries, --connect, downgrade, DNS seeds, broadcast, rebroadcast) with per-cell mechanism + test. The audit caught `resolve_seeds` running a LOCAL DNS lookup under `--proxy` — the exact boundary-failure class of Core's June-2026 advisory — now gated. New cells tested: retry-also-via-proxy (mock SOCKS observes ≥2 dials, zero peers). `proxy_unreachable` event ships. Open: downgrade-under-proxy wire test, 24h capture. | [matrix](../docs/PRIVACY_MATRIX.md) |
| 68 | 09-24 | Fixed-size send cells | Can the wire write-size histogram be flattened? | **adopted — queue #17 closed** | `set_cell_bytes` on session/manager + `--cell-bytes` on run/sync: `flush` pads the send queue to a cell multiple with decoy packets (v2 only — v1 has no ignorable type; fill<20B overshoots to the next boundary, preserving alignment). Test: every flush emits a cell-aligned byte count incl. a small ping after version; v1 stays unpadded. Kernel-level segment splitting is the observer-visible residual (documented). | — |
| 67 | 09-24 | Documented observability surface | Is the event/telemetry surface consumable as an API? | **adopted — queue #33 closed** | `docs/OBSERVABILITY.md`: the full machine-readable layer as one documented surface — `getevents` ring (7 event kinds incl. eclipse_suspected, recon_divergence, cpu_throttled), `getpeerinfo` telemetry (cpu_ms, recon diffs, addr budgets, claims-vs-delivered), `getmempoolinfo` lifecycle+shadow, block receipts + validation report, swiftsync artifact RPCs, and the poll-drain consumption contract (1024-deep ring, newest-first). | [observability](../docs/OBSERVABILITY.md) |
| 66 | 09-24 | UTXO-replay self-audit | Can the coins layer be audited like stored blocks? | **adopted — queue #15 closed** | `audit_utxo_segment(from, to)`: the reorg-safety invariant over connected segments — every undo-claimed-spent coin is dead, every live created coin matches its block output, and at tip every non-live created coin is provably spent (present in some undo). Provably-unspendable outputs and sub-tip segments handled honestly (nonlive-created half only asserts at tip). Periodic pass runs a ~2-week window each audit interval. Test: 120-block spend chain clean; a removed live coin → UndoMissing. | — |
| 65 | 09-24 | Shadow-ruleset observatory | Can policy drift be measured live without gating? | **adopted — queue #8 mempool side shipped** | Every `accept_tx` also scores `shadow_standard` — a Knots-style strict envelope (42B datacarrier total, single nulldata output, no bare multisig) — recorded in `ShadowStats`, surfaced as `getmempoolinfo.shadow` {evaluated, divergent, by_reason}. Never gates: a divergence is a counter, not a verdict. Tests: datacarrier/bare-multisig/2-output cases diverge under shadow while the pool still accepts; strict-vs-ours unit coverage. Block-level shadowing stays open. | — |
| 64 | 09-24 | Stem relay on recon links | Does the stem delay survive BIP-330's set-sync model? | **adopted — queue #7 closed** | Two fixes: stem inv candidates now exclude recon links (an inv to one breaks the model), and `recon_pool` filters stem-pending txids out of the sketch — a scheduled round would otherwise carry the tx to the recon peer inside the 2-15s delay, making the hop decorative. Test: recon peer gets no inv, pending txid absent from sketch ids, present again after fluff. | — |
| 63 | 09-24 | ASMap text-map loader + --asmap wiring | Can operator-supplied maps drive bucketing end-to-end? | **adopted — queue #21 usable** | `AsMap::load_file` parses `a.b.c.d/plen asn` rows (`#` comments, malformed lines counted not fatal — a partial map buckets, a wrong one misleads silently). `--asmap <path>` on `run`/`sync` → `SyncConfig.asmap_path` → `mgr.set_asmap` at startup. Core's bit-packed kartograf `asmap.dat` parsing stays the open remainder. Test: rows parse, longest-prefix wins through the loader, bad lines counted. | — |
| 62 | 09-24 | Per-peer dispatch CPU accounting | Can per-peer CPU be measured AND enforced without disconnecting the sync leader? | **adopted — last PEER_BUDGETS row closed** | `cpu_ns` cumulative + `cpu_rate_ns` decayed-per-second on every `dispatch` call; enforcement = skip the dominant peer's `poll()` when >50% share at >200ms/s — socket backpressure throttles it, no disconnect (IBD leader dominance is legitimate). `cpu_ms`/`cpu_rate_ms` in `getpeerinfo`; `CpuThrottled` NetEvent via `getevents`. Test: dominant peer's buffered ping goes unanswered while a quiet peer is served. | — |
| 61 | 09-24 | Per-block verification receipts | Can every connect produce machine-checkable evidence? | **adopted — queue #5 core shipped** | `connect_block_full` returns a `BlockReceipt` per connect: script_flags enforced, fees/sigops, checks queued vs verified-cache skips, spent/created counts, wall_ns, and `delta_commitment` — SHA-256 over the exact UTXO transition (per-tx: txid, spends, creates, block order), replayable by construction. Journal ring (2016) in Chainstate covers all three real connect paths — tip extension, reorg `simulate_branch` (the sim IS the connect), and assumeutxo background replay. `getblockreceipts`/`getblockreceipt` RPCs. 4 tests: field correctness, replay determinism, delta sensitivity, both-sides-of-reorg journaling. A standalone replay-verifier tool + bundle export stays open. | — |
| 62 | 09-24 | SwiftSync protocol machinery | Can the aggregate ride the real UtxoSet mutation paths? | **adopted — machinery shipped; sync integration open** | `swiftsync.rs` module (TagAgg/coin_tag/Hints wire format) + `UtxoSet::enable_swiftsync`: `agg == Σ tags(live)` held across every mutation class incl. overlay-commit and lower-layer shadowing; `swift_hold` suppresses mid-window flushes, `release` restores them; `emit_hints`/`verify_hints` give producer artifact + consumer verdict — wrong hints waste the optimization, never corrupt the set. `AVILA_SWIFTSYNC=1` opts in at coinsdb open. | [swiftsync](2026-09-24-swiftsync-write-elision.md) |
| 61 | 09-24 | SwiftSync aggregate mechanics on the real chain | Does created−spent == Σ survivors hold at real scale? | **confirmed — protocol verified; sync-path integration open** | `swiftsync_bench` replays the node's own 229,113-block signet main chain (70 side-branch excluded): 22.4M created, 15.0M spent in-window — **67.0% of coin writes elidable** — aggregate exact with zero drift; dropped-survivor fraud breaks the equality; transient map peaks ~682 MiB; hints artifact = 36B/survivor outpoint list + commitment (267MB for this chain). | [swiftsync](2026-09-24-swiftsync-write-elision.md) |
| 60 | 09-24 | Mempool tx-lifecycle / RBF ledger | Can the node answer "what happened to every tx" natively? | **adopted — closes queue #32** | Every removal path tags its cause (`RemovalCause`: confirmed, block-conflict, replaced{by}, evicted, expired, reorg-drop, explicit) — recorded inside `remove_inner`, the one funnel all removals pass through. `LifecycleStats` counters (accepted/rejected/parked_orphans/replacements + per-cause removals) ride in `getmempoolinfo.lifecycle`; a bounded 4096-deep ring backs `getmempoolhistory` (newest first, RBF events carry the replacing txid). 6 tests: verdict counting, replacement linkage (conflict+descendant both tagged), confirmed-vs-block-conflict, expiry, eviction, ring bound. | — |
| 59 | 09-24 | Process sandboxing (minimal) | Can the node take a real OS-level defense without new risk? | **adopted — no_new_privs always-on** | `prctl(PR_SET_NO_NEW_PRIVS)` at sync start via the `prctl` crate (workspace forbids unsafe). A wire-parser compromise lands in a process that can never escalate via setuid/file caps — and the node never execve()s, so it costs nothing. seccomp syscall filtering and Landlock datadir scoping stay open (bigger dep surface). | — |
| 58 | 09-24 | Fail-closed proof (unit) | Can "no clearnet when proxied" be tested, not assumed? | **yes — test shipped** | Mock SOCKS5 listener records connections; a routable candidate + refused proxy greeting yields: proxy saw the dial, zero peers established. A clearnet bypass would be observable as "proxy saw nothing". The 24h live packet-capture artifact stays open. | — |
| 57 | 09-24 | Fail-closed proxy | Does `-proxy` actually cover all outbound traffic? | **fixed a real leak** | `SyncConfig.proxy` covered only `--connect` peers — `maintain_outbounds`' dial worker connected clearnet regardless, and `seed_from_dns` resolved locally. Now every automatic dial routes through the SOCKS5 proxy (no clearnet fallback — a dead proxy = no peers, not a leak) and DNS seeding is skipped under proxy (Core's `-onlynet=onion` model). | — |
| 56 | 09-24 | Per-peer budget contract | Are the adversarial limits a published, tested spec? | **adopted — doc** | `docs/PEER_BUDGETS.md` enumerates every per-peer resource bound with enforcement point and proving test; the honest gaps are named at the bottom (per-peer CPU dispatch, recon bisection cap, getcf* rate limiting). | [PEER_BUDGETS.md](../docs/PEER_BUDGETS.md) |
| 55 | 09-24 | Eclipse indicators | Can the node notice it's being eclipsed? | **adopted (indicators)** | `eclipse_signals`: TipStale (>24h-old tip while ≥4 peers all claim higher), DiversityCollapse (all outbound in one /16), AllInbound (every established peer dialed us). Fires `NetEvent::EclipseSuspected` once/minute; sync logs it, `getevents` exposes it. Indicators, not proof — disjoint-route cross-check (#10) is the escalation. | — |
| 54 | 09-24 | Continuous self-audit | Can the node re-prove stored blocks cheaply? | **adopted** | `audit_block` re-verifies a stored block's internal proofs (decode + merkle root + witness commitment — no historical UTXO needed); the sync loop samples 8 random heights per 2016 connected blocks, seeded so an adversary can't predict which regions are checked. Loud failure line + cumulative counter. Live UTXO-replay auditing stays open (needs undo-walk). | — |
| 53 | 09-24 | Sovereign wallet stack completion | What does the watch-wallet surface still lack? | **mostly built; history RPCs closed it** | `getwalletinfo` (descriptors, scan floor, gaps) + `listtransactions` (synthesized receive/send history from per-coin lifecycle) — the stack already had importdescriptors/listdescriptors/listunspent/getbalances/rescanblockchain/deriveaddresses/listreceivedbyaddress + Electrum server + silent-payments watches. The "one binary replaces the EPS/bwt stack" claim is now actually checkable. | — |
| 52 | 09-24 | Named observability surface | Can the node stream "what it's doing" natively? | **adopted (ring-level)** | `getevents` RPC over a capped 1024-entry `NetEvent` ring in the manager — connects, disconnects, tip advances, announcements, newest first. The `chain_query` channel carries it; mempool/consensus event classes extend it next. ASMap bucketing machinery also landed (#21): ASN-aware outbound dial deprioritization, kartograf-format parsing open. | — |
| 51 | 09-24 | Mempool analytics (block projection) | Can the node answer "next N blocks" natively? | **adopted** | `block_projection` sorts the pool by modified feerate into ~1MvB virtual blocks; `getmempoolblocks` RPC returns per-band min/median/max feerate + fees — the mempool.space query without the stack. Package-aware ordering (full template machinery per chunk) noted as the refinement. | — |
| 50 | 09-24 | Dual-engine lockstep (fixture) | Do redb and hashstore diverge on identical commit streams? | **no — 300 rounds identical** | Same mixed create/delete stream committed to both engines; sampled `get` parity after every commit + full `iter_coins` equality at the end. Production live-shadow plumbing stays open; the fixture proves the engines are behaviorally equivalent. | — |
| 49 | 09-24 | Self-fuzzing canary | Do mutated blocks ever misdecode silently? | **no — 4000 mutants clean** | `mutated_blocks_never_misdecode`: seeded xorshift mutates a real block (bit flips, truncations, extensions, splices); every surviving decode must re-encode byte-identical. The standing red-team harness inside the decoder. | — |
| 48 | 09-24 | Selfish-stem relay + first-spy sim | Does a 1-hop stem on own-txs hide origin? | **adopted — 5× reduction** | `stem_announce`: own txs inv one random outbound peer, fluff after 2-15s randomized delay; no stempool (dodges the DoS that killed BIP156), zero protocol change. Sim (`tools/firstspy_sim.py`, 300-node graph, 15% spies, 4k runs): first-spy names origin 68.9%→14.4% — residual ≈ spy density. | experiments/2026-09-24-selfish-stem.md |
| 47 | 09-24 | Transport hardening triplet | Can cheap defenses close documented leaks? | **adopted ×3** | Non-deterministic inbound eviction (Springer evict-and-fill needs steerable picks — now uniform-random among unprotected); V2 decoy injection (~1-in-4 sends carry random-length IGNORE packets, spec-legal, receivers drop silently — fuzzes the length histogram the 2025 analysis classified commands from); recon-diff telemetry (per-peer rounds+misses in getpeerinfo — persistently-wide diff = censorship signal). | — |
| 46 | 09-24 | Pinning red-team + oracle | Do the documented BIP-431 attacks land, and can we detect them? | **both attacks work; oracle detects** | Descendant-limit pin: 25 junk descendants off the attacker's output → victim's own-output CPFP rejected `PackageLimits` (counterfactual bump accepted clean). Rule-3 pin: 64-output low-feerate conflict prices out a high-feerate small bump → `Conflict`. Oracle: `pinning_risk()` + `getpinningrisk` RPC flags txs within margin of the descendant cap — the test asserts it catches the attack. Generic detection shipped; wallet-labeling waits on #29. | — |
| 45 | 09-24 | Broadcast pool (Core #30471) | Can own-txs survive fee-spike eviction? | **adopted** | `sendrawtransaction` entries persist outside `map` (300kB cap, oldest-evicted); a 60s `rebroadcast_pass` re-admits + re-announces with 60s→4h exponential backoff; entries drop when inputs confirm-spend elsewhere (UTXO-resolved dead check); persists through a mempool.dat tail section. The "my tx silently vanished" class is closed. | — |
| 44 | 09-24 | SwiftSync write-elision churn measurement | How much UTXO write load dies within a sync window? | **confirmed — pursue prototype** | 183,884 real signet blocks parsed: 63.3% of all created coins are spent within the window — never needed on disk. Median coin lifetime 2 blocks; 47% of spends same-block; 88% within 1000. The aggregate+hints path would eliminate ~2/3 of coin writes. Caveat: signet churn ≠ mainnet; attacks write tail, not the ~95% script-verification bulk. | [swiftsync](2026-09-24-swiftsync-write-elision.md) |
| 43 | 09-24 | Repeated-key aggregation in advised ECDSA | Can duplicate public-key terms remove more arithmetic from #40? | **additional CPU win; elapsed benefit inconclusive** | Same 24-block Script replay: ordinary 25.274 CPU s → previous advice 19.133 → repeated-key worker 16.705 (another −12.7%; −33.9% vs ordinary). Historical arithmetic kernel −21.9%; unique-key control +0.3%, within variation. Regtest gains little. 27 kernel + 33 replay comparisons, 95 boundary/protocol checks, and native sanitizer suites pass; same verdict/UTXO hashes and invalid-spend rollback. Same hints and Rust binary; production unchanged, full mainnet IBD unmeasured. | [repeated-keys](2026-09-24-ecdsa-repeated-keys.md) |
| 42 | 09-24 | BIP-330 tx delivery live + two real sync bugs | Does set reconciliation carry a real transaction end-to-end? | **verified live; bugs fixed** | Two regtest nodes over BIP324-v2: tx mined into A's pool reached B's via sketch diff → reconcildiff ask (33B) → body (430B) → B's mempool — **zero inv announcements** (tx-invs suppressed on recon links). Live run flushed two real bugs: inv bursts >16-slot window were consumed-and-forgotten (fixed: `pending_blocks` drain), and restore was O(n²) via `ancestor_is_invalid` walking to genesis per header on a clean chain (fixed: O(1) early return; 66k headers went 3:45min → instant). | [erlay-sketch](2026-09-24-erlay-sketch.md) |
| 41 | 09-24 | Zero-copy assumeutxo activation (overlay) | Can `loadtxoutset` activate without importing 170M coins? | **adopted — single-pass, persists** | `activate_snapshot_overlay`: `index_with` builds the sparse index AND streams decoded coins to the commitment hasher in one sequential read; `SnapshotRun` attaches as the lowest UtxoSet layer. Fixture (13k coins): 0.01s single-pass vs 0.03s import; the win is zero duplication + bounded memory, not small-scale latency. `snapshot.path` sidecar re-attaches on resume; `state.dat` carries the delta only (`iter_delta`); `UtxoSet::iter` merges the layer for dump/stats consumers. Resume test: drop+reopen resolves all base coins. | [delta-overlay](2026-09-24-delta-overlay-shim.md) |
| 40 | 09-24 | Compact ECDSA advice and verification-time production | Can portable advice be small, streaming and cheaper to supply? | **qualified offline experiment; production unchanged** | Mainnet stream 3.57 MB → 146 KB (24.42× smaller); recipient CPU −23.7%. Production + packing 51.35 → 29.13 CPU s (−43.3%); 64-job producer groups improve elapsed. 129 comparison runs + 9 scheduling runs + 133 checks pass; 482 unit tests pass, 2 existing ignores. One already-validating producer + one recipient repays added CPU at sample medians. Full mainnet IBD and online exporter unmeasured. | [advice-economics](2026-09-24-ecdsa-advice-economics.md) |

| 39 | 09-24 | Parallel ECDSA advice with bounded recovery | Does the replay gain survive eight workers, bad hints and durable state? | **qualified offline prototype; not enabled in production** | 3 repeats: mainnet Script CPU 25.05 → 19.29 s (−23.0%), elapsed 19.80 → 16.43 s (−17.0%); complete regtest CPU −7.2% RAM / −5.3% disk+reopen. All-corrupt advice retries 7,351/183,782 checks in 8 bounded groups, +2.5% CPU vs ordinary. 93 replay runs + 10 additional checks; invalid-spend rollback and UTXO hashes pass; 479 unit tests pass, 2 existing ignores. Tradeoffs: sampled summed RSS 59 → 180 MiB; framed sidecar 3.57 MB; two-pass preparation 54.38 s. Full mainnet IBD unmeasured. | [parallel-replay](2026-09-24-ecdsa-parallel-replay.md) |

| 38 | 09-24 | Fetch-frontier scan fix | Was the sync scheduler the bottleneck? | **adopted — ~5x live throughput** | fill_queues re-sorted the whole header index per peer per tick (O(peers x headers)). Now: cached height-index rebuilt on growth + one shared scan from the connected frontier. Signet: 1.7 -> ~9 blk/s; in-flight saturates the 16/peer window (peer RTT is the limiter now). | [fetch-frontier](2026-09-24-fetch-frontier.md) |

| 37 | 09-24 | Utreexo accumulator spike (rustreexo) | Does the ~1KB-state validation primitive work? | **promising — measured on 1M leaves** | Stump = 247B state vs ~50MB set (~864B at 170M vs 12GB). 2000-spend block batch: 16.5KB proof, 17.9ms verify+apply (~1% block bandwidth). Bridge build 566k leaves/s. Integration = program (bridge-node proofs + BIP-181 wire), not patch. | [utreexo](2026-09-24-utreexo-spike.md) |

| 36 | 09-24 | Differential fuzzing vs Knots | Do random block mutations diverge verdicts? | **working — 1080 mutations, 0 consensus divergences** | `tools/diff_fuzz.py`: seeded mutations (merkle/tx/witness/truncate/count) on ~125 real regtest blocks through both submitblock. One strictness class documented: header-identical mutations → Core dup-shortcircuits, Avila strict-decodes first. Ordering, not consensus. | [diff-fuzz](2026-09-24-diff-fuzzing.md) |

| 35 | 09-24 | Erlay recon — pure-Rust minisketch | Is the sketch primitive tractable without C++ FFI? | **adopt (primitive) — works + measured** | ADOPTED intra-Avila: sketch.rs + recon.rs — GF(2^32) minisketch, BIP-330 wire set, salted short-ids, sendrecon negotiation, 4s scheduled rounds. LIVE on real TCP over BIP324-v2: recon:true in getpeerinfo, sustained reqrecon/sketch exchanges both directions. 512B sketch reconciles what 1.28MB inv sends. Remaining: non-empty-pool misses, reqbisec, external interop. | [erlay-sketch](2026-09-24-erlay-sketch.md) |

| 34 | 09-24 | Address-index cost model | What does the Electrum-style index cost? | **measured — build ~free, serve needs disk-backing** | Spend fixture: connect delta ~0% (8.56s vs 8.64s); scindex.dat ~38B/entry. In-mem by_script map ~46B/entry → ~200GB at mainnet — the query layer needs hashstore backing (bounded refactor, already designed). | [addr-index](2026-09-24-address-index-cost.md) |

| 32 | 09-24 | Live network sync (signet) | Can the node sync against real peers? | **works — fetch scheduling is the limiter** | Signet, DNS-seeded: 208 blocks connected in 15.4s; resumed run reached 1124 blocks/66k headers in 640s (~1.7 blk/s — in-flight stays 0-96, scheduler conservative; validation never the bottleneck). Resume works. Mainnet-scale unproven. | [live-signet](2026-09-24-live-signet-sync.md) |
| 33 | 09-24 | Delta overlay — snapshot as lowest UTXO layer | Can SnapshotRun serve as the read base under the delta? | **partial adopt — read shim done, tested** | `UtxoSet.snapshot` fourth layer; `SnapshotRun::index` portable fallback indexer. Overlay test found 2 real get() bugs: EOF window clamp + zero-count-group underflow on misses. 480 tests pass. activate integration (attach+snapverify+persist) deferred — touches Claude's patch area. | [delta-overlay](2026-09-24-delta-overlay-shim.md) |

| 31 | 09-24 | Verification-transparency ledger | Can the node report its own trust state as a typed value? | **adopted** | `Chainstate::validation_report()` + `getvalidationreport` RPC: connected/header heights, snapshot base+commitment+replayed_height, assumed/unproven ranges, verified_fraction. Snapshot test: fresh→replay→verified 0.0→1.0; full node 1.0. | [validation-report](2026-09-24-validation-report.md) |

| 30 | 09-24 | Speculative block pre-validation | Can a predicted mempool template pre-pay connect work? | **SUBSUMED by #20** | 625-block spend fixture, 512MiB cache: baseline 6.6s (script 6268ms) → verified-prediction 257ms (script 0ms, 25.7×); +prefetch 289ms — worse, read was already 9ms. Verified-tx cache captures the whole win; residual is apply+bookkeeping, no lever. Mainnet ~90% overlap untested — live-sync's job. | [predict](2026-09-24-spec-block-prediction.md) |

| 29 | 09-23 | One-byte ECDSA advice through real Script and chainstate replay | Does #27's kernel gain survive recipient overhead and false signature results? | **replay win; full mainnet IBD unmeasured** | One script thread, 3 repeats: 24 actual mainnet blocks / 183,782 ECDSA attempts, including 6,137 false results: 27.65 → 18.41 s (−33.4% elapsed, −29.0% combined CPU). Complete 625-block regtest replay: 6.17 → 4.22 s, identical 12,995-coin UTXO hash. Early 501-block mainnet loses 22.9% elapsed (only 10 checks). Mainnet hints 183,782 B; two-pass preparation 57.18 s separately; bad parity + whole-sample retry 61.66 s. Script edge cases, hostile/missing hints, worker exit and sanitizer/protocol tests pass. Isolated copied workspace, probabilistic batching, no production changes by this experiment. | [historical-replay](2026-09-23-ecdsa-historical-replay.md) |

| 27 | 09-23 | Native ECDSA batching with untrusted nonce advice; deterministic batch inversion | Does #19 rule out faster local signature verification? | **kernel win; not integrated IBD** | Same pinned libsecp, 16,384 synthetic signatures, 3 repeats: 127.56 CPU µs/sig ordinary → 70.06 with 1 B advice (1.82×) or 56.11 with 33 B (2.27×), batch 8,192. Helper generation 130.60 µs/sig separately; random batch acceptance. Bad advice + fallback costs 44–58% extra CPU. Deterministic no-advice batch inversion saves only 0–3%. Adversarial, cancellation and rare-x tests pass with ASan/UBSan/VERIFY. | [ecdsa-advice](2026-09-23-ibd-ecdsa-advice.md) |

| 26 | 09-23 | Audit read floor; authenticated snapshot directory | Can startup avoid the whole-file index scan? | **prototype: prepared open 0.14–0.25 s** | Same synthetic 170M coins / 9.31 GB: raw cold-advised reads 11.4–13.1 s; 38.96 MB authenticated directory opens in 0.14–0.25 s across six runs, with 2,594/2,594 coin-body checks each. Preparation costs 23.55 s separately and requires a trusted root; not integrated node startup. Pipelined full scan 21–56 s: no reliable sub-20 s win. Revises #25's physical-floor interpretation. | [read-floor](2026-09-23-snapshot-read-floor.md) |

| 25 | 09-23 | Index-only load (SnapshotRun) | Is the copy itself the cost? The snapshot file is already the right format | **170M in 20s — ~8.3M coins/s** | Original interpretation (see #26 correction): ~130MB/s writes → the 11.4GB run can't go faster (~85s). Sparse index over txid-group starts (442k entries, ~19MB) + seek-reads into the file itself → 20s index build, 2.8k/s point reads. Usable node ~3-4min was an estimate, not an integrated-node measurement. File must persist + delta layer for writes. | [sortedrun](../crates/avila-consensus/src/sortedrun.rs) |

| 28 | 09-23 | Snapshot load at disk speed + midstate-hint verification | The 20 s "read floor" is a page-cache/CPU artifact, and Core's sequential hash check can be split across cores without new trust | **scan 25 s → 5.1 s; verified load 13.8 s** | Drive is NVMe (990 EVO Plus, PCIe 3.0 x4), not SATA: O_DIRECT reads 9.3 GB in 3.5 s (2.5–2.7 GB/s) vs 16.7 s buffered single-thread. Writes really are slow (0.15–0.32 GB/s O_DIRECT), so index-only stays right. 170M file, same box, load ~12: parallel exact scan (resync + stitching, 8 thr) **5.1 s**, 0 fallbacks, vs old `runindex` 25 s cold. Streaming `hash_serialized_3` straight from the file (no 170M-coin materialization; matches `coinstats` in tests) 18.8 s sequential; **13.8 s** with untrusted SHA-256 midstate hints (140 hints = 17 KB, same hash; ~20 CPU-s, so ~3–4 s idle-box est., unmeasured). Found: old byte walkers skip Core's VARINT `n++` (desync on scripts ≥122 B), `decompress_amount` can panic under overflow-checks. Zero-scan (interpolation) lookups: **unfinished** — phantom resync inside big groups; tests ignored | [snapverify](../crates/avila-consensus/src/snapverify.rs) |


| 24 | 09-23 | SortedRun bulk-load (LSM base layer) | Can the B-tree be bypassed? The stream is already key-sorted | **12.4× ingest — 170M in 106s** | decode-only 4.06M/s (42s) proved insert = 97% of time; redb ceiling ~140k/s (4 shards → 109k/s, worse — I/O bound). SortedRun: sequential append + sparse index (512 stride, ~15MB RAM) → **1.6M coins/s, 11.4GiB, 3.7k/s reads**. Usable node ≈ ~4-6min vs Core ~10min+. Needs delta overlay to go live | [sortedrun](../crates/avila-consensus/src/sortedrun.rs) |

| 23 | 09-23 | Snapshot load at 100M→170M scale (hash vs redb) | Does snapshot ingest scale to mainnet size? | **hash cache-cliffs; redb 129k/s at 170M** | redb: 100M in 653s (153k/s, 7.4GiB) → **170M in 1315s (129k/s, 12.5GiB, 3.5k/s reads)** — measured at real mainnet scale. hash: ~18k/s — random probes on 12.9GB index miss page cache; `reserve()` pre-size 7ms vs ~17 resize rewrites. **Headline: usable node ~25min (headers + 22min load + 8.7GB file)** | [snapshot_bench](../crates/avila-consensus/examples/snapshot_bench.rs) |

| 22 | 09-23 | assumeutxo time-to-usable (end-to-end) | Does snapshot load beat full sync? | **144× to usable tip** | 625-blk fixture: full sync 4.4s vs headers+snapshot-load 0.03s; background_step verifies all 625 pre-snapshot blocks in 4.2s (honest, not trusted). Load ~650k coins/s → mainnet est ~4-5min for 170M + ~4GB snapshot file; **pooled background_step: 4.4s→1.7s (2.6×)** — snapshot path now beats classic sync on *both* time-to-usable AND time-to-fully-verified | [assumeutxo_bench](../crates/avila-consensus/examples/assumeutxo_bench.rs) |

| 21 | 09-23 | Head-to-head vs Knots 29.3 (same fixture) | Is Avila actually faster than Core-family? | **1.76× validation throughput** | Knots Connect total 2456ms/628blk (256 blk/s); Avila spec-connect ~1.4s wall (~450 blk/s); sequential ~215 blk/s (~0.84× serial). Edge = cross-block barrier elimination, not crypto. On mainnet-dense blocks the gain shrinks toward tail-overlap bound | — |

| 20 | 09-23 | Verified-tx cache (mempool→block dedup) | Mempool-verified txs re-verify at connect — skip them | **adopted** | 15,364 hits/0 misses on spend fixture; connect script share → ~0 for seen txs (2.9s→0.17s per 625 blocks); flag-containment rule (block_flags ⊆ verified_flags) keeps it sound across softfork boundaries | see sigchecker::mark_scripts_verified |

| 19 | 09-23 | ECDSA batch cost model (k256 primitives) | Can SP-batch beat libsecp's 92µs/sig? | **REJECTED for tested implementation** | batch-of-8 ≈43ms vs 736µs individual (~60× slower): k256 scalar mul alone (120µs) exceeds a whole libsecp verify; SP resultant ~41ms. This rejected the k256/SP path, not all ECDSA batching. The original fixed-floor interpretation is superseded by #27's isolated native/advice experiment; production integration remains open. | [probe](../crates/avila-consensus/examples/ecdsa_batch_probe.rs) |

| 18 | 09-23 | ECDSA batch feasibility (research spike) | Can standard (r,s)-only ECDSA batch-verify? | **feasible-bounded; scope corrected by #27** | Original SP proposal: ~2× at batch ≤9, unmeasured whole-node gain and high implementation risk. The missing-R objection applies without advice; #27 tests locally checked out-of-band hints for unchanged historical signatures. Changing on-chain encodings is not required for that experiment; randomized acceptance and helper costs must be explicit. | [ecdsa-batch](2026-09-23-ecdsa-batch-feasibility.md) |

| 17 | 09-23 | End-to-end sync pipeline timing | Is connect the bottleneck of the whole accept path? | **adopted — decisive** | connect=97% of wall (scripts ~92%); decode+headers+flush ~3%. Spec-connect's 2× is real end-to-end; storage is ~1.5–4% of the node at this scale; next lever on the dominant share is algorithmic (batch sig verify) | [sync-pipeline](2026-09-23-sync-pipeline.md) |

| 15 | 09-23 | Speculative cross-block script pipelining | Persistent pool + deferred wait overlaps serial N+1 with drain N | **adopted (exp-grade)** | 205→520 blocks/s (2.5×) on 26-tx/blk fixture — density-flattered; mainnet-dense expected 5–15%; rollback+mark_invalid on pending failure verified | [spec-connect](2026-09-23-speculative-connect.md) |

| 14 | 09-23 | Connect phase timing | UTXO storage share of validation unknown | **adopted — decisive** | 625 spend-dense regtest blocks: scripts ~95%, read+apply ~3.5%, 0 backend commits under cache; engines identical. Storage wins are capacity/ingest, not latency; cross-block script overlap is the real lever | [connect-timing](2026-09-23-connect-timing.md) |

## Pending / running

- Inline small records into the slot (wide-slot variant) — the 2-page
  touch per read is structural; only colocating record with index
  slot cuts it to 1.

## Queued candidates (proposed, not started)

Listed in rough priority; each entry has the hypothesis and the cheapest
first measurement that would kill or confirm it.

1. **Snapshot activation without materialization.** The overlay shim
   (#35) proves reads fall through; `activate_snapshot` still bulk-loads
   via `utxo_snapshot::load` + `coinstats::compute` (OOMs at 170M).
   First step: attach `SnapshotRun` in place + wire snapverify (bounds
   already verified) + persist the anchor.

2. ~~**Verified-artifact distribution format.**~~ **spec done — `docs/ARTIFACT_BUNDLE.md` (committed d4e2640).** Replay + parallel-verify
   are proven (astra's ecdsa-parallel-replay); the open item is the
   artifact spec — one reproducible bundle (snapshot + index +
   midstates + sig-hints) anyone can generate and verify against
   anchors. First step: write the format spec.

3. **Utreexo as a first-class UTXO backend.** #38's spike shows a
   247-byte accumulator state vs the 12GB UTXO set, ~110k leaves/s
   verify+apply. First step: an `UtxoBackend` impl over rustreexo
   `Stump` + a proof-carrying connect path on the fixture chain.

4. **Erlay follow-through.** Intra-Avila is live end-to-end (sketch →
   reconcildiff → body, zero inv announcements). Remaining: capacity
   tuning on realistic pool diffs, multi-peer round overlap, and
   external interop (nobody else speaks BIP-330 — Knots if they ship
   it).

5. ~~**Per-block verification receipts.**~~ **done — #61 (receipts + RPC shipped; standalone replay tool open).** Extend the transparency ledger
   to per-block machine-checkable records: flags active, sighash modes,
   script counts, UTXO state-hash before/after, wall time. Exportable
   and independently replayable. Audits the node; never substitutes
   for verifying it.

6. **Proof-carrying blocks (utreexo consumption).** Blocks carrying
   their own accumulator proofs validate against a ~1KB stump — no
   UTXO set needed. Parallel proof-verify / sequential apply; node can
   also serve proofs. Purist gate: needs self-bridge or conventional
   fallback — a bridge can starve, never forge.

7. ~~**Stem-phase tx relay on top of recon.**~~ **done — #64 (stem pending excluded from recon sketches until fluff).** Recon rounds are already
   the epidemic "fluff"; add a private stem path for N hops before the
   tx joins the reconciliation pool. Honest limits: propagation
   latency, known Dandelion deanonymization attacks.

8. ~~**Shadow-ruleset observatory.**~~ **mempool side done — #65 (block-level open).** Read-only evaluation of every block
   under alternate rulesets (Knots policy, proposed softforks) — a
   continuous consensus-drift monitor. Must never gate acceptance.

9. ~~**Dual-engine lockstep mode.**~~ **done — #63 (shadow-backend plumbing; fixture + live replay).** Two independent validation paths,
   divergence halts with alarm. Note: bitcoinkernel shares Core's code
   (common-mode bugs survive); true independence needs a second
   implementation lineage.

10. **Multi-route sync.** Disjoint transports cross-checking headers —
    eclipse detection by construction.

11. **Process-level sandboxing.** (minimal shipped — #59 no_new_privs always-on; seccomp/Landlock stay open) seccomp/capability separation: the
    P2P stack can't write the datadir, the validator can't open
    sockets, RPC gets its own boundary. Nobody ships OS-level
    containment in a node. Measurable: publish the syscall whitelist,
    test what a compromised wire parser can actually reach.

12. ~~**Eclipse detection (not just resistance).**~~ **done — #55 (indicators shipped; disjoint-route cross-check open).** Watch the signatures —
    stalled header progress, suspiciously-uniform peer agreement,
    work plateau — and cross-check disjoint routes to prove it. Lab
    experiment: mount a real eclipse, measure detection time.

13. ~~**Fail-closed privacy profile.**~~ **done — #57 (found + closed a real leak: proxy didn't cover automatic dials or DNS seeds).** Tor unreachable → tx broadcast
    stops, Electrum stops, RPC stays localhost. Privacy failure
    becomes impossible-by-configuration, not merely unlikely. Nobody
    ships this because it's annoying; it's the only honest privacy
    promise.

14. ~~**Per-peer adversarial accounting.**~~ **done — #56 + #62 (contract fully enforced).** Formal per-peer budgets —
    bytes, CPU, memory, queue slots — as a *tested contract*: fuzz the
    boundaries, prove no hostile peer exceeds allocation under any
    input sequence.

15. ~~**Continuous self-audit.**~~ **done — #54 + #66 (UTXO-replay layer now covered).** Background re-verification of random
    historical segments, forever — correctness as an ongoing property,
    catching disk rot and bitflips. Each pass appends receipt evidence.

16. ~~**Pinning oracle.**~~ **done — #46 + wallet-labeling.** Mempool watcher that detects pinning patterns
    against the operator's wallet transactions — descendant-limit
    saturation, RBF rule-3 pinning, parked conflicts — and reports it.
    The node tells you when you're under attack; nobody ships this.
    Real value for LN operators.

17. ~~**V2 traffic padding.**~~ **done — #47 + #68 (decoys + fixed-size cells).** The 2025 v2-transport analysis showed
    BIP324 encrypts content but leaks message *shape* via TCP payload
    lengths. BIP324's decoy/garbage mechanism exists for exactly this —
    nobody uses it. Experiment: fixed-size send cells + decoy traffic;
    measure observer command-classification accuracy before/after.

18. ~~**Selfish-stem broadcast.**~~ **done — #48.** The DoS objection that killed BIP156
    was relaying *unvalidated* stems. Variant: only locally-originated,
    mempool-admitted txs take a stem hop — one outbound link,
    randomized delay, then normal recon fluff. No stempool, no
    unvalidated relay, most of the origin-privacy benefit.

19. ~~**Recon-diff censorship telemetry.**~~ **done — #47 + #62.** Every recon round already
    computes the per-peer pool diff — surface it. A peer persistently
    missing a large share of your mempool is a censorship/eclipse
    signal. Security telemetry at zero protocol cost.

20. ~~**Non-deterministic inbound eviction.**~~ **done — #47.** The evict-and-fill attack
    (82-97% linkage accuracy) exploits predictable eviction; randomize
    it. Small, bounded.

21. **ASMap bucketing.** (machinery shipped — #52; kartograf-format map loading open) Core's deployed Erebus countermeasure —
    bucket peers by ASN (Kartograf-reproducible maps) instead of /16.
    A parity gap; well-specified, bounded.

29. ~~**First-class watch-only wallet.**~~ **done — getwalletinfo + listtransactions shipped.** Descriptor/xpub import, balance
    and history, no keys on the node, answers through the Electrum
    server already shipped. Five+ separate projects (bwt, EPS,
    xpub-watcher, Fully Noded, eps-plugin) exist solely because this
    is clunky on Core. One binary replaces the wallet-backend stack.

30. ~~**Broadcast pool.**~~ **done — #45.** Own-broadcast txs survive
    eviction + rebroadcast. (Future-dated broadcast still open.)

31. **SwiftSync-style write-elision IBD.** Hash aggregate (all outputs
    minus all inputs = UTXO set) + untrusted hints file marking
    survivors; coins that die young never hit disk. Core is landing
    this now (PR #34004); our advice machinery fits it exactly.
    First measurement: what fraction of fixture coins die within the
    sync window.

32. ~~**Built-in mempool analytics.**~~ **done — #51 + #60.** The mempool.space layer native:
    mempool-block fee forecast, tx lifecycle/RBF tracking, pinning
    surface (compounds with #16). People stand up docker+mysql+electrs
    for this today.

33. ~~**Named observability surface.**~~ **done — #67.** Package existing per-peer
    claims-vs-served, timing, recon state as the documented
    event-stream API — literally Core issue #34901 ("block processing
    is a black box"), which we already satisfy.

34. **Evidence server.** Compact filters (shipped) + PoW fraud proofs
    + artifact bundles served to the operator's own light clients —
    your phone trusts your node.

22. ~~**Self-eclipse field test.**~~ **done — lab mount passes (coordinated all-attacker set flagged).** Build the attack: attacker nodes that
    monopolize all our outbound slots in a lab topology. Hypothesis:
    detection signals (header stall, peer homogeneity, route
    uniformity) fire within bounded time. Kill condition: our own
    eclipse goes undetected — learn it now. Nobody publishes eclipse
    experiments on their own node; even a negative result is tooling.

23. **Pinning red-team.** (#46 descendant-limit + rule-3, plus
    eviction-cap shipped) Three BIP-431 vectors now proven: the
    descendant-limit pin, the rule-3 absolute-fee pin, and the
    multi-party eviction-cap pin (4 shared txs × full junk trees → a
    sweep replacement must evict 101 > MAX_REPLACEMENT_CANDIDATES →
    `TooManyReplacements`). Implement BIP-431's documented pinning
    attacks as tools (descendant-limit saturation, rule-3 pinning,
    package-limit pinning), run against our mempool on regtest.
    Hypothesis: oracle catches all documented classes with bounded
    false positives. Kill: pinning is indistinguishable from
    legitimate high-descendant usage — the signal isn't separable.

24. ~~**Continuous dual-engine lockstep.**~~ **done — #63.** (fixture-scale proven — #50; live-shadow plumbing open) We already have two coins
    engines (redb + hashstore) — run both permanently on live traffic,
    divergence = halt. Continuous consensus-equivalence as a running
    property. Kill: second-engine overhead impractical at steady state
    — measure it.

25. **The privacy proof artifact.** (mechanism-level proof shipped — #58 unit test; the 24h capture run stays open) Private mode + 24h full outbound
    packet capture. Hypothesis: zero non-Tor bytes escape. Kill:
    anything leaks (DNS, NTP, stray v1) — publish exactly where.

26. ~~**First-spy simulation.**~~ **done — #48.** Implement the first-spy timing estimator
    from the Dandelion literature; run against our relay with/without
    selfish-stem. Hypothesis: stem measurably moves detection
    probability. Kill: stem-length-1 doesn't move the needle — learn
    the number before building the real thing.

27. ~~**Self-fuzzing canary.**~~ **done — #49.** The node continuously feeds mutated
    recent blocks back through its own strict decode path — a standing
    red team inside the node. Kill: generated mutations aren't
    interesting enough to catch what a test suite misses.

28. ~~**Adversarial live-wire suite.**~~ **done — live-wire test (garbage/oversized/inv-flood) passes.** Hostile peers at max rate —
    malformed messages, floods, slowloris — measure per-peer budgets
    hold under sustained attack. Kill: a hostile peer can starve
    honest peers — find the hole now.

35. **Signing core.** (partial — opt-in signer shipped) The wallet
    becomes a signer: `createdescriptorseed` builds a BIP84 account
    (OS CSPRNG or caller-supplied hex entropy — provenance recorded),
    installs a memory-only `SignerState` (secrets NEVER hit
    `watchlist.dat`), and tracks the neutered xpub descriptors via
    the real import path. `walletprocesspsbt` signs with
    `Creator::Real` — real RFC6979 low-R ECDSA + deterministic
    schnorr. Verified: descriptor-derived keys sign and finalize a
    spend. Open: `sendtoaddress`/funded-PSBT + coin selection,
    encrypted-at-rest vault, `getnewaddress`.

36. **UTXO-verified signing + signing receipts.** The differentiator:
    the signer checks every PSBT prevout claim against the node's own
    *verified* UTXO set — the LSB-010 fee-attack class solved
    structurally (Trezor's fix requires full prevtxs; we have the
    chain). Every sign emits a receipt: sighash, checked amounts,
    fee delta. Hypothesis: a node-attached signer can enforce
    no-unverified-amounts without prevtx bloat. Kill: none — the
    property is enforceable by construction; measure the UX cost.

37. **Entropy ceremony.** (partially shipped) `createdescriptorseed`
    now accepts `dice` (ASCII rolls — SHA256 over digits, Coldcard-
    compatible so seeds cross-verify against the firmware's own
    derivation; <50 rolls errors, <99 warns, >30% single-face skew
    warns) and `mix` (XOR-folds OS CSPRNG into caller entropy — no
    single bad source decides). Commit-before-generate: `sha256(raw
    input)` is recorded and reported as `entropy_commitment` — the
    provenance claim is checkable, not asserted. Tests prove the
    derivation convention and mixing. Open: BIP39 mnemonic rendering
    of the seed, encrypted-at-rest vault, entropy-input file source.

38. **Fingerprint self-measurement.** (shipped) `txfp::analyze` scores
    a tx against the published heuristics — BIP69 ordering, anti-fee-
    sniping nLockTime, RBF sequence value, low-R grinding, version,
    round-payment detectability — and reports the profile it matches.
    `fingerprintcheck` exposes it over RPC. Verified: our sendtoaddress
    construction scores `core` (the mimicry target); a sorted/zero-
    locktime fixture scores `electrum-like`. Open: feed per-spend
    scores back into wallet responses; cluster-level analysis needs
    graph context a single tx lacks. Run the published wallet-
    fingerprint taxonomy (BIP69 ordering, anti-fee-sniping nLockTime,
    nSequence value, low-R grinding, coin-selection shape, change
    position — ~50% single-tx identification accuracy in the
    literature) against our own tx construction. Configurable
    fingerprint policy: mimic-dominant vs strict-uniform. Hypothesis:
    we can measure and control attribution signal; a distinctive
    construction is itself a tell. Kill: no policy meaningfully lowers
    measured identifiability — report that too.

39. **Signer process boundary.** (shipped) `avila-node signer` is a
    hidden subprocess: the node spawns it with the vault path +
    passphrase over a stdin handshake, then pipes PSBTs as JSON-lines;
    keys never exist in the node process. `signerspawn` installs the
    boundary on the wallet; `walletprocesspsbt`/`sendtoaddress` verify
    prevouts in-process then sign in the child; `signerlock` drops it.
    Live-tested: a spawned child unlocked a real vault and produced a
    final witness. Honest ceiling: same kernel — defense-in-depth, not
    an airgap. The key store + signer in a separate
    process with a narrow IPC (PSBT in, signed PSBT out); the P2P
    process holds no key material. Same kernel — defense-in-depth, not
    airgap — but ahead of shipped Core multiprocess. Hypothesis: full
    compromise of the wire parser still can't reach keys; measure the
    IPC signing latency. Kill: latency breaks interactive use.

40. **Deferred-deps wallet work.** MuSig2 key-path multisig
    (rust-secp256k1 `musig` module — needs bump from our 0.29),
    silent-payments *send* (libsecp sender API), Payjoin sender
    (BIP78/77). Queue only after 35–37 land.

41. **Corpus-parallel script replay.** The load-bearing IBD
    hypothesis ([physics doc](2026-09-26-ibd-physics.md)): script
    verification needs only corpus-resolved prevouts, never the UTXO
    set — so the whole history's sig work is embarrassingly parallel.
    First measurement: replay the signet corpus, resolve prevouts
    from the block store (txid→position index), measure sig/s vs
    worker count. Kill: scaling sub-linear past ~4 workers.

42. **UTXO set as anti-join.** Replace incremental point mutations
    with one batch operation: partition created/spent records by
    outpoint-prefix, probe per partition, emit survivors. Sequential
    I/O only. First measurement: run both paths over the 22.4M-create
    signet window, compare wall + bytes-written. Kill if <5×.

43. **IFMA/SIMD lane-parallel sig kernel.** ECDSA verify is
    branch-free → 8 independent sigs in AVX-512+IFMA lanes
    (5×52-bit limbs), ~6–8×/core on Zen4+/IceLake+. Subprocess worker
    keeps `unsafe` out. First measurement: kernel bench vs the
    `ecdsa_advice` harness baseline. Kill <3×/core.

44. **GPU crypto-plane worker.** sig+SHA256d offload via subprocess
    (same boundary as the advice harness). Published ~4M verifies/s
    midrange GPU — discount 2×. First measurement: minimal
    verify-only kernel, bit-exact vs CPU path on the adversarial
    corpus. Kill <10× aggregate or any unmatched edge case.

45. **Canonical corpus encoding + any-source fetch.** Deterministic
    re-encoding (positional outpoints, compact sigs, template tags,
    pubkey dictionary, compact amounts, zstd) — projected ~20–30%.
    Plus trust-free fetch: torrent/HTTP/LAN source, verified locally,
    since source honesty is irrelevant under full validation. First
    measurement: real byte savings on the signet fixture. Kill <15%.

46. **P2P fetch-rate ceiling on mainnet.** Before betting on
    acquisition alternatives: measure the achievable sustained
    fetch rate across N real peers vs link speed. Establishes how
    much of the model is reachable without #45. One bounded run.

47. **Trusted-cluster sharded validation.** Split height ranges
    across operator-owned machines; each validates its shard,
    coordinator merges the anti-join (partitions by outpoint-prefix
    shard cleanly). First measurement: two-machine regtest split.
    Kill: merge cost eats the parallel gain.

## Exp6 — scripthash/address index cost model (measured)

`scindex_bench` over `fixtures/signet-blocks-000000-000300.dat` (300
real signet blocks, now that the bench recognizes signet magic):

- Connect-time delta with the index on: **+3.6%** (0.05s baseline).
- `scindex.dat` log: 31,581 bytes / 601 entries = **~53 B/entry**.
- 601 unique script hashes over 300 blocks ≈ 2.0/block (signet is
  mostly coinbases to fresh addresses — faucet-shaped).
- In-memory ~42 B/entry (32B hash + (h, pos, txid) rows).

Projection: signet-scale is trivial (~16 MB at 150k blocks); a
mainnet-wide address index extrapolates to the multi-GB range — the
cost model confirms the opt-in profile design. Bounded measurement,
not a live full-chain run.


## Security audit remediation (AUDIT-2026-09-24)

External audit of `2bf8bab` (+`d661e72`): 3 critical, 16 high, ~25
medium, plus lows/slop. All findings fixed and verified:

- **Criticals**: `getdata` streaming serve with byte budget (was:
  whole-request materialization, any peer could OOM the node);
  entropy commitment domain-separated (was: commitment == seed, and
  `signerload` echoed it); dice floor 10→50 rolls + `mix` defaults on.
- **Highs**: walletprocesspsbt refuses unverified inputs; coin
  selection excludes mempool-spent + immature coinbases; wallet fee
  ceiling (0.10 BTC/kvB); `listreceivedbyaddress` no longer panics on
  silent-payment coins; SP scan keys moved to the vault (watchlist
  keeps public material only); vault+watchlist 0600 + fsync +
  overwrite guard; `createdescriptorseed` refuses a loaded signer;
  pre-auth header parser panic closed (Unicode case-fold length
  bug) + duplicate-CL rejected; RPC slot leak on panic (drop guard);
  Electrum subscription rescan now change-gated, per-connection pump
  lifetime + sub cap; reqrecon rate-limited; BIP35 `mempool` is
  inbound-only + capped; outbound netgroup diversity without asmap;
  per-command traffic counters bounded; misbehavior now discourages.
- **Mediums/lows**: addrman per-source insert quota (P2P-6); stem
  hop is per-epoch (P2P-7); zeroize on all key-bearing types;
  argon2 off the sync thread; named-param validation; PSBT sighash
  honored; testmempoolaccept maxfeerate; pinning-risk `mine` gated;
  addnode hostname never hits local DNS under `-proxy`.
- Deferred: the ~1k-line RPC boilerplate dedup (slop, zero security
  value — tracked separately); unsalted swiftsync tags (audit itself
  flags safe-today).

Commits: `fd54db4` (criticals+highs), `a623909` (mediums+lows),
`1acc2b5` (P2P-13 residual). Workspace release tests green.

## Exp8 — live differential vs Bitcoin Knots 29.3 (real P2P + RPC)

`experiments/diff_knots.sh` spawns a fresh Knots regtest daemon (105
mature coinbases), syncs avila-node from it over real P2P, then diffs
`testmempoolaccept` verdicts on a shared corpus.

- INTEROP: synced all 105 blocks over **v2-negotiated BIP324**
  transport. Earlier stall was environmental (a leftover process
  holding the connect target), not a wire bug — captured wire bytes
  were verified correct. `sendrecon` pre-verack "unsupported" log on
  Knots' side is expected: BIP330 negotiates in the same slot as
  wtxidrelay; Knots doesn't implement Erlay.
- DIFFERENTIAL: valid spend allowed by both; mutated (witness byte
  flip) rejected by both (knots `non-final`, ours
  `mandatory-script-verify-flag-failed`); garbage hex rejected by
  both (knots top-level RPC error, ours `TX decode failed`);
  orphan spend rejected by both (`missing-inputs` ≈
  `bad-txns-inputs-missingorspent`). **Verdicts aligned 4/4**; reason
  strings differ in wording only.
- Harness bugs found + fixed: cookie file is the full `user:pass`
  (was double-prefixing), `-rpcwait` for the cookie race, params[0]
  of testmempoolaccept must be the rawtxs array.

## Exp9 — mainnet IBD first light (2026-09-25, in progress)

First real mainnet run (`avila-gui --config config/mainnet.toml`,
`prune_mb=2048`, assumevalid on). Live evidence only; no fixtures.

- DNS seeding + outbound formation: 7–8 established peers within ~40s
  of a cold start, mixed IPv4/IPv6, v2 transport negotiated.
- Low-work header presync against real peers: ~940,000 headers
  buffered and committed in under ~2 minutes once a stable leader
  held (~8,500 hdr/s sustained, single sync peer).
- Header tree absorbed the committed chain at ~48k/min while block
  connect began in parallel (early-era blocks ~20/s; dense-era rate
  still unmeasured).
- Pruning now runs in-loop every 60s (was shutdown-only — archival
  IBD would have needed ~700GB transiently).
- In-flight bugs found by watching real traffic, fixed in `4d7de93`:
  - duplicate `getheaders` per peer (Established + leader election)
    poisoned per-peer presync continuity → leader churn loop;
  - non-leader presync buffers with suppressed continuations leaked
    `headers_in_flight` → mass `headers_timed_out` drops;
  - CPU throttle starved the headers leader's socket → remote peers
    closed the one connection feeding sync (exempt now);
  - orphan block announcements during IBD punished as misbehavior —
    `Acceptance` is now `Option`; unknown-parent defers (Core
    semantics) instead of disconnecting;
  - leader election preferred arbitrary peers — now prefers a peer
    that has already served headers; leadership resumes a peer's
    presync from its buffered tip rather than re-asking from genesis;
  - DiversityCollapse grouped IPv6-mapped IPv4 peers into one bucket
    (`ip[0..2]`) — canonical `addrman::net_group` now + regression
    test (`v4_mapped_peers_in_distinct_sixteens_do_not_collapse`);
  - GUI autostart waited for the first frame callback — an occluded
    Wayland window never got one, so the node silently never started
    (start moved into `App::new`; SIGTERM now routes through the
    viewport close so `on_exit` flushes state).
- Visibility: `SyncProgress.headers_buffered` surfaces presync
  progress to the banner — previously the tree tip stayed 0 through
  the whole presync and read as "stuck".
- Open: full-chain connect time unmeasured; presync buffer is not
  persisted across restarts (leader loss mid-presync restarts it —
  cheap at current pace, expensive only if it lands mid-phase);
  leader is still a single peer, matching Core.

- Stall eviction was the wedge on real mainnet (found via wire
  telemetry + live probes): `BLOCK_STALLING_TIMEOUT` = 2s dropped any
  peer whose first `getdata` answer took longer than 2s — under a full
  16-block request burst real peers regularly need longer — so every
  connection died ~2s after `Established`, churned the addrbook, and
  never let headers or blocks flow. Symptom looked like peers muting
  us (handshake-only rx maps, zero post-verack traffic); probes proved
  the same code+messages work instantly on a fresh socket.
- Fix, matching Core's stall recovery: `stalled()` now *releases* the
  peer's in-flight reservations back to the fetch pool (`release_in_
  flight`) so answering peers poach the work; disconnect only after 4
  consecutive poach cycles with no delivery. Any `block` arrival —
  even a late poached one — resets the counter (`block_delivery_
  resets_the_stall_counter`, `stalled_peer_is_poached_then_dropped_`
  `after_repeated_stalls` cover both halves).
- Live evidence (debug build, mainnet): after the change the node
  holds 7-8 peers with `in_flight` ~96-128 and connected height
  advanced 8458→12394 through restart+resume; prior runs churned
  40+ peers in 2 min with zero post-handshake traffic.
- Also fixed while in there: `version` nonce was the dial port
  (8333) for every outbound — now a per-connection random u64 so
  outbound sessions are distinguishable and our self-connect check
  works as designed.

- Snapshot activation fused verify+index (#1 queued candidate):
  `activate_snapshot_overlay` now runs `snapverify::verify_stream`
  (or `verify_hinted` when a `<file>.avhints` sidecar exists — first
  activation writes it; midstates are recomputed per interval so a
  bad sidecar only fails closed). ONE pass yields the hash check AND
  the sparse overlay index — the old path built them as
  index_with + compute_streaming on the same read.
  - 170M real fixture (9.3 GB): stream 12.8 s, hinted 11.0 s
    (8 threads, busy box — idle estimates ~3-4 s); 25M: 2.1 s/1.8 s.
    Identical hash both paths; old path ~25 s index alone.
  - Two latent `SnapshotRun::get` bugs found by a new
    index-equivalence test (`snapverify_index_answers_identically_`
    `to_index_with`, `sparse_window_reaches_coins_past_any_fixed_cap`):
    * fixed 128 KiB read window vs stride-65536-group sparse entries
      (~7 MiB gaps on mainnet) → false misses for ~97% of coins;
      window now bounds at the next sparse entry / EOF.
    * `pos + 33 > n` early-exit assumed every next record was a group
      header — dropped records within ~33 B of a window end.
    * `index_with` wrote sparse-key vouts little-endian vs the
      big-endian `outpoint_key` search form — wrong ordering for any
      group whose first vout ≠ 0.
  - Impact: without these fixes a real activate_snapshot_overlay run
    would have attached an index that silently answered "absent" for
    most snapshot coins — consensus-visible corruption once
    background validation spends them.

- Utreexo accumulator backend — first-class path (#3 queued):
  `crates/avila-consensus/src/utreexo.rs`. `UtxoAccumulator` wraps a
  rustreexo `Stump` (roots + leaf counter only — ~864 B state at
  mainnet scale vs the 12 GiB set) persisted to `utreexo.stump`.
  `connect_block_proven` is the proof-carrying connect path: caller
  supplies the block's spend set + an accumulator `Proof`; membership
  verifies the *coin bytes* (leaf = sha256d(outpoint_key ||
  compact_record) — Avila scheme, not BIP LeafData), completeness is
  checked input-by-input, then the unmodified `connect_block` runs on
  a spend-only overlay and the stump applies adds+dels.
  - Soundness: a forged coin fails the leaf-hash check before any
    consensus work; a missing bundle entry is `MissingSpend` (bridge
    starvation is a stall, never a bypass).
  - Tests: synthetic regtest chain over the same scaffold as
    connect.rs — grow past maturity, then a two-input spend block
    connects via proof end-to-end while a conventional `UtxoSet` run
    cross-checks; tampered-bundle + unbundled-input + reopen-persist
    coverage.
  - Not yet: reorg/undo (rustreexo's UpdateData makes it possible),
    proof serving (MemForest bridge), p2p bundle transport (#6).

- Erlay follow-through — adaptive sketch capacity (#4 first piece):
  capacity was `pool_len/64` — sized by OUR set, not the diff a
  sketch actually decodes. A 40k pool round-tripped a 512-symbol
  sketch (~2 KiB) for a steady-state diff of tens. Now a per-peer
  `recon_diff_hint` records the largest decoded diff (fast rise,
  half-decay per quiet round) and capacity = `2*hint + 32` clamped
  [16, 1024]. A bisect event doubles-hints so the next round skips
  the bisect trip. Still to measure on a live node with a real
  mempool — capacity waste only matters once pool diffs are real.

- Proof-carrying block transport — codec layer (#6 first piece):
  `utxproof` P2P message carries a block hash + an opaque spend
  bundle whose byte format is owned by consensus
  (`utreexo::encode_spend_bundle`/`decode_spend_bundle`: compact-size
  spend count bounded at 1M, per-input `(outpoint, coin)` records via
  the existing compact-coin codec, then the rustreexo `Proof`
  serialization runs to payload end). The frame-level 4 MiB cap and
  `d.finish()` trailing-byte rejection bound the wire side; the
  consensus decoder rejects malformed coins and bad proofs before
  any trust. P2P stays opaque — no coin encoding duplicated in the
  transport crate. Tests: round-trip, truncated hash, over-declared
  var-length, trailing garbage (167 p2p tests, 544 consensus all
  green). Not yet: negotiation, serving path (needs an in-memory
  forest at connect time — proofs can't be generated post-hoc for
  spent leaves), fetch-side consume wiring, real-connection test.
  Honest status: scaffold only — nothing sends or consumes
  `utxproof` yet.

- **utxproof transport + bridge + shadow consumer — verified on a live
  pair (queue #6 done).** Regtest two-node test: producer with
  `--utreexo-bridge` (proving `MemForest` on a dedicated worker —
  `Rc` internals are `!Send`, so chainstate ships `(block, undo)`
  records over a bounded channel; a `ProofReader` serves `proofs.dat`
  via offsets + `pread`), consumer pinned by `--connect` with
  `--utreexo` (negotiates `sendutxproof`, decodes wire bundles,
  replays `connect_block_proven` in chain order — no UTXO set).
  Chain carries a real spend at h120 (spends the matured h1
  coinbase) so non-empty proofs crossed the wire. Result:
  consumer reached `h 150 | utx 150` — the shadow stump has the
  whole chain proven-connected from bundles alone, persisted
  (`utreexo.stump`), and status line reports the shadow height.
  Two real bugs found by the live test:

  1. `fetch_index` only rebuilt when ≥2048 new headers arrived —
     during bulk sync that works, but the tail of a download (or
     regtest's single 150-header page) never trips it: the index
     stayed at genesis, zero blocks were ever requested, sync
     wedged permanently. Now rebuilds whenever the index doesn't
     reach the known tip. Suspect for the earlier mainnet h112229
     freeze.
  2. `BitcoinNodeHash` serializes as a *tagged* enum — 1 byte for
     Empty/Placeholder, 33 for Some — not a bare 32-byte hash. The
     defensive pre-decode bound written as `16+8t+32h` rejected
     every non-empty proof (e.g. `16+8+6·33=222`), so the first
     real spend's bundle read malformed and shadow replay stalled.
     Rewritten: min-width bounds (t ≤ spends, t ≤ bytes/8,
     h ≤ remaining bytes — each hash ≥1B) keep every
     `with_capacity` under the payload, then a `Cursor` enforces
     exact consumption — no trailing bytes. Regression test pins
     the actual on-disk bundle bytes.

  Also fixed along the way: `proofs.dat` opened non-append
  overwrote the magic+records on restart (now `O_APPEND` + torn-tail
  truncation on open); `pending_bundles` capped; shadow drive capped
  per call so proof replay can't monopolize the sync thread.

- **Stored-body replay no longer OOMs or wedges — and reports itself
  end-to-end (queue: crash recovery).** A datadir carrying ~13k
  stored-but-unconnected bodies exposed three compounding pathologies
  in `resume`: it decoded *every* stored body into a `Vec<Block>` at
  once (RSS balloon → the kernel OOM-killed the desktop under a
  30 GB-no-swap box), retried the whole set per leftover pass
  (quadratic), and ran `best_bodied_descendant` + a `chain_set`
  HashSet rebuild per connected block (O(n²) at datadir scale).
  Fixes: positions-not-bodies replay (height-sorted, lazy decode,
  single linear pass + one leftover retry), DFS capped at 2048
  visits, O(1) height-indexed fork walk, tick-loop replay gated to
  tip-children only. Evidence: bounded 4 GiB run replayed 13,290
  bodies with flat ~800 MB RSS and monotone `restore: replay
  N/13290 (tip H)` milestones.

- **Startup phases are now real, not inferred.** `SyncProgress`
  gains `phase: Phase` published from the first line of `run`
  (Opening / RestoringHeaders / VerifyingChain / ReconcilingBackend
  / ReplayingBodies / FindingPeers / Syncing) — the GUI can no
  longer show a frozen `connected` while a 40-minute backlog replay
  runs underneath, which was exactly the "sync appears wedged" UI
  lie. Chainstate carries an optional `ProgressEvent` sink
  (`None` = silent, as before); `with_store_coinsdb_progress`
  threads it through open/restore/resume. GUI renders a `Starting`
  lifecycle phase + per-phase banner with determinate counters
  (headers restored N/M, replay done/total + live tip) — no
  ambiguity about what a number means. Locked in by
  `resume_reports_progress_phases` (asserts the event sequence and
  counts on a synthetic 100-body parked backlog).

- **IBD pace fixed: the ~570ms/block overhead was a broken skip-list
  transcription, not validation cost (queue: real mainnet IBD).**
  Per-block instrumentation (`accept_ns`/`reorg_ns`/`seg_ns`/
  `sim_checks_ns`) on a live datadir copy isolated ~55ms inside
  `script_checks` → `is_ancestor` → `get_ancestor`, which walked
  `prev` pointers linearly — ~800k hash lookups per connect at
  968k-header scale (~460ms/blk). Implementing Core's `pskip` skip
  list exposed a transcription bug: `GetSkipHeight` written as
  `InvertLowestOne(InvertLowestOne(h-1)) - 1` where Core has `+ 1`
  (chain.cpp: "max 110 steps to go back up to 2^18 blocks"). The
  `-1` variant produced degenerate skip pointers — measured 2057
  hops for a 20k→1 descent and ~200k hops/blk at probe scale.
  With `+1`: worst case 15 hops over all 2^18 descents, ~70 hops
  for a real 968k→150k probe. Result on the real datadir copy:
  `script_checks` 55ms/blk → ~30µs/blk; total `accept_block`
  ~570ms/blk → ~3-11ms/blk (~100×). `connect_block` (real
  validation, ~0.6-6.5ms) is now the dominant cost — as it should
  be. Guard rails: `get_ancestor_full_descent_is_log_n` asserts
  <500 steps for 5 full-depth descents over a 20k chain; the
  `ancestor_steps` diagnostic counter and `sim_checks` timing
  bucket remain for live verification.

- **IBD crash-recovery cascade fixed: torn state.dat can no longer
  poison the chain (queue: real mainnet IBD).** An OOM kill mid-flush
  left `state.dat` truncated while `coinsdb.redb` held ~214k heights of
  committed UTXOs. On restart, `resume()`'s restore-failure arm rebuilt
  the chainstate at genesis but reattached the ahead backend without
  rewinding — replaying block 1 against a 214k-height coin set failed a
  spend check, `mark_invalid` cascaded to ~24k descendants, and a
  shutdown checkpoint persisted the bogus marks. Layered fixes:
  `resume` logs the restore error instead of silently discarding it;
  the rewind target is the rebuilt tip, not a stale reference;
  `reconcile_backend` rewinds in bounded 2048-height commits so a
  34k-height gap costs 17 transactions instead of 34k (the old
  per-height loop took ~30min — observed live); `tip_height` can be
  clobbered to 0 by a torn meta write so the ahead-probe uses
  `tip_height().max(max_undo_height())` (undo records commit atomically
  with the coins they reverse — can't lie low); rewind failure on
  missing bodies wipes+rebuilds coinsdb from blk files rather than
  attaching mismatched state.

- **Restart-under-pruning fixed: `restore` treated pruned bodies as
  corruption → every restart discarded the checkpointed chain.** The
  chain-verify required `store.position(hash)` for every connected
  entry — but the position index is rebuilt from surviving blk files,
  so pruned bodies read as absent → `corrupt("connected block body
  not stored")` → silent rebuild → the ahead-backend check then
  computed tip=0 and tried to rewind a healthy ~214k backend to
  genesis, failing on pruned bodies and wiping coinsdb. Net effect:
  restart under `-prune` reset the node to genesis (observed live —
  a 175,002-block checkpoint at restart became "tip 0" replay).
  Fixes: `open` infers `pruned_through` from the lowest surviving
  blk file; chain-verify accepts absent bodies when pruning is
  active; restore error printed before fallback.

- **The real wedge: peer CPU budget `continue` skipped the rate-decay
  fold → dominant download peer permanently quarantined.** Three
  separate live wedges (147,629 / 140,378 / 134,384 / 214,850) shared
  one signature: the next-needed hash `reserved_by` one peer with
  `have_body=false` while in-flight churned below it. Diagnostics
  (`pos`, `age`, `recv` per reservation) showed the hash pinned at
  queue position 0, aging 246s+, on a peer with blocks_received frozen
  at 3,775 — the fastest server had tripped the 200ms/s throttle, and
  the fold that halves `cpu_rate_ns` sat BELOW the `continue` that
  skips throttled peers, so its rate never decayed: once dominant,
  permanently dead to us. Its getdata response for the frontier block
  arrived and sat unread on an unpolled socket. Hoisting the fold
  above the throttle check restores temporary-backoff semantics.
  Supporting hardening: peer order rotates each `fill_queues` tick
  (stable HashMap order had been landing the frontier block on the
  same peer every release cycle); `NODE_NETWORK_LIMITED`-only peers
  are never offered heights below their ~288-block retention floor
  (a pruned peer silently drops the getdata and re-pins the hash);
  the aged frontier hash gets a duplicate reservation on the
  least-loaded peer each tick (`want_one`); fetch-stall diagnostics
  now print services/pos/age/recv; the self-audit skips pruned bodies
  (`body_stored` distinguishes policy-absent from store-lost).

- **Memory under real IBD bounded via cgroup knowledge:** RSS
  plateaus ~6.6GB during bulk connect (allocator steady state); the
  earlier 5.7GB→OOM deaths were cgroup page-cache writeback charged
  to `MemoryMax`, not heap — `MemoryHigh` below `MemoryMax` throttles
  writeback instead of killing. `MALLOC_ARENA_MAX=2` bounds arena
  proliferation. The dirty-map budget (`over_budget`) fires correctly
  once connect flushes see it; the 736MB-map overshoot was a
  poisoned-state symptom, not a cache bug.

- **Pace model ETA:** flat `blocks/min` extrapolation lies during IBD —
  era cost varies ~30× (empty-2010 vs dense-segwit blocks). Implemented
  a windowed model: every 1024 connected blocks records
  (end height, wall ms, block count, Σ encoded bytes via
  `store.position().len`); pace = F + R·bytes/blk where R = ratio
  estimator Σwall/Σbytes over outlier-filtered recent windows (stable
  where least-squares over-fits n=4 noise into 397h) and F anchors at
  the median window; bytes/blk regressed on height, clamped to
  [median, p95×4 ≤ 4MB]; predicted pace clamped to [p95×4 cap,
  floor]. Integrates per-window to the header tip. First live read at
  h~373k: ~35h — vs flat extrapolation's misleading ~4h.
- **Replay bypassed the flush check:** `accept_block`'s
  `AlreadyKnown`+`have_body` arm and the unlinked-descendant arm
  returned `maybe_reorg` results directly — no `over_budget` check.
  Replay/backlog drains rode those arms exclusively, letting the dirty
  map reach 5.2M entries/688MB and stall commits for minutes (D-state
  worker under cgroup writeback throttle). `needs_flush` (bytes OR
  1M-entry bound) now runs after every `maybe_reorg` merge; branches
  truncate at 256 blocks per batch.
- **Stale undos survived rewinds:** `commit_inner` only inserted undo
  rows; a backend rewind left rows above the new tip, so
  `max_undo_height` reported the pre-rewind chain and re-triggered the
  ahead-of-state repair on every restart (~10min wasted per boot).
  Tip-stamping commits now delete undo keys above the tip in the same
  transaction.

## 2026-09-26b — Speculative connect completion boundary (audit Work Order A)

**Finding:** `docs/IBD_EXECUTION_AUDIT_2026-09-26.md` was right —
`enable_speculative_connect` (shipped with run23) had no completion
boundary: `Acceptance::Connected` returned while ≤8 script checks were
still in flight, so `mempool.on_block_connected`, `TipAdvanced`/relay
announce, RPC heights, and `validation_report` all treated unverified
blocks as authoritative; a short tail could sit undrained forever.

**Fix (8a8ea5a, d19eac9):** a `checked_feed`/`checked_height`
completion boundary in chainstate — blocks become observable to
mempool/relay/RPC only when their checks pass; drains push `(height,
hash)` to the feed; non-speculative connects push at accept.
Short-tail drains run on a 50ms idle tick. Deferred failures set
`spec_failed` (peer attribution) and rewind the bad suffix; pending
entries drop on reorg/invalidate; flushes drain before committing.
RPC generate/submitblock and the sv2 template path drain before
answering. All authoritative reads (`getblockchaininfo`,
`getchainstates`, `getchaintips`, `getbestblockhash`, GUI tape,
SyncProgress) report the checked frontier.

**Verification:** new live tests over `testpipe` real sessions —
`speculative_short_tail_failure_is_never_published` (bad script in a
≤8-deep tail: nothing announced or fed, drain rewinds to the prefix,
sender attribution resolves) and `speculative_valid_tail_publishes_on
_drain` — plus 3 chainstate boundary tests. 553+9+19 consensus, 170
p2p, 108 node tests green; clippy clean.

**Live:** run24 resumed at 407,176; replay + sync healthy with the
bounded pipeline (RSS ~2.3GB, flush bounds holding).

## 2026-09-26c — ETA: calibrated interval, era-bound caps (47d82c3)

**Finding:** the point ETA quoted "4 days" (110h) at h~417k — an
inflation, not a stall. Two clamps double-counted the same
densification: `byte_cap = p95_size*4` let the far-tail prediction
float to the 4MB protocol edge (a per-block edge, never a sustained
mean — real segwit-era means plateau ~1.3-1.6MB), and `pace_cap =
p95_pace*4` let the priced pace quadruple on top. The ratio estimator
`Σwall/Σbytes` also let one wall-heavy window bend the cost slope.

**Fix:** `R` is now the median per-window ms/byte; `byte_cap` is
era-bound (`1.5×` the worst measured window mean); `pace_cap` is
`2.5× p95`. More importantly, `eta_secs` now returns
`(lo, central, hi)`: lo holds every remaining block at the measured
median-era cost, central follows the size regression frozen at the
evidence horizon, hi prices every block at the dense-era ceiling.
`SyncProgress`/`NodeView` carry the interval; heartbeat prints
`mid[lo..hi]`; the GUI banner shows the range.

A single ETA over ~550k heterogeneous blocks is fake precision — the
calibrated band is what the measurements actually support. Verified:
108/108 node tests; the running node continues on the corrected
build (windows warming).

## 2026-09-27 — Gate 4 COMPLETE: real-window comparison, byte-exact

**Result:** the join engine validated a complete real mainnet window —
heights 454,001–454,301 (301 blocks) — against a genuine `dumptxoutset`
boundary at h454,000 (45,616,695 coins, txoutset-hash
`00617975…1f581c`, all three pins enforced) and materialized an end
state that is **byte-for-byte identical** to the node's independently
produced chainstate at h454,301: 3,594,371,786 bytes, 45,751,759 coins,
sha256 `865d32cfaea57e15352ece551685dd71d9b96ea39f8118cc0ca0152b44cd3168`
on both sides.

**Checks run:** 968,778 headers through production `HeaderTree::insert`
(full PoW/nBits/MTP path) with 0 failures; 1,303,682 non-coinbase inputs
resolved with 0 missing, 0 conflicts, 0 dup-spends; 615,503 txs through
context-free + coinbase-bound + maturity + value + locktime + sigops +
**BIP68 (all evaluated, 0 violations, 0 unevaluated)**; all queued script
jobs completed (`verified_inputs = inputs_noncb`).

**Timing (guarded, one job at a time):** `window_join` wall 112 s —
stages: parse 5.2 s, emit 1.3 s, boundary load inside join 28.6 s,
predicate 0.9 s, scripts 38.5 s (8 workers), materialize 4.4 s,
export 17.0 s. Peak RSS 10,239 MiB under `guard_run --max 10240`.
Run manifest `corpus-454k/run-manifest.json` ties build_rev
`c80d991+dirty`, binary/corpus/boundary/headers/export SHA-256s, argv.

**Required structural fix:** `HashMap<OutPoint,Coin>` for 45.6M coins
peaked >14 GB (two memcg kills under the cap — machine safe both times).
Replaced with `FlatBoundary` (one sorted `Vec` of 64-byte records + one
append-only script blob + alive bitmap; ~4.2 GB steady, no rehash
transient). `join_window` is now generic over a `BoundaryView` trait
(HashMap impl kept for corpus-derived boundaries). Also fixed:
`boundary.clone()` at stage E (full-map dup), `loaded.clone()` at
spec-check, `window_lo/hi` now min/max over heights (blk-file order is
not height order — cosmetic field only), wasteful `boundary.keys()`
iteration removed from the join.

**Resources:** `tools/guard_run.sh` (cgroup MemoryMax + swap 0 +
preflight refusal) now mandated by AGENTS.md; verified live three
times (two cap-kills, machine untouched).

## 2026-09-27b — real-window CORRECTION run: full contextual coverage

Per the real-window audit, the first comparison was missing
`contextual_check_block` and did not bind header-context failures to the
selected chain. Fixed and re-run under the guard:

- `contextual_check_block` (BIP34 cb-height, witness-commitment /
  unexpected-witness, block weight, full finality incl. coinbase) now
  runs per block with the real parent MTP from the production HeaderTree:
  `ctx_block_evaluated=301/301`, zero failed, zero unevaluated.
- Header context is bound to the selected chain: `node.height == corpus
  label`, `CHAIN[h] == corpus hash`, `CHAIN[454000] == donor base hash`,
  and a window header that failed production insert is invalid —
  `headers_{height,chain}_mismatch / failed_selected / missing_selected`
  all zero; unrelated bad index entries no longer taint the run.
- Blocks process in verified chain order (`sort_by_key(height)`);
  corpus/BLK file order had 6 backward transitions.
- `--require-complete` is the checked complete-run entry point: exit 0
  only iff `window_complete` (all pins + header context + ctx blocks +
  coverage + zero unresolved). `chainstate_complete` is now real.
- Export is streamed (merge-iterate alive bitmap + overlay, inline
  sha256) — the 3.6 GB output Vec is gone; run peak dropped ~2 GiB.

**Corrected receipt** (`corpus-454k/run.log`, `run-manifest.json`):
exit 0 under `guard_run --max 8192`; wall **83.7 s** — parse 4.1, emit
1.3, headers 3.4, boundary-load 11.3 (inside join 23.5), predicate 0.8,
scripts 31.8 (8w), materialize 4.1, export 14.7 — stages account for the
wall. Process RSS HWM 7,057 MiB; cgroup sampled peak 8,191 MiB vs
8,192 MiB cap. Export identical sha `865d32cf…44cd3168` (3,594,371,786 B)
== `snap_to_canonical` of donor-454301 (`corpus-454k/comparator.log`,
guarded, exit 0): **byte-exact end state confirmed with complete checks.**

Regression suite now 96 checks incl. genesis-rooted manifest fixtures:
wrong cb height → BadCbHeight reject; witness data sans commitment →
UnexpectedWitness reject; PoW-pass/ctx-fail header on the selected chain
→ reject; corpus label ≠ chain height → reject; missing selected header
→ no complete acceptance; out-of-order corpus → still complete; flat
oracle (untouched boundary coin + same-block create/spend) → survivors
exact.

## 2026-09-27c — completion-contract controls (real-followup audit)

Three audit findings closed:

- **Requested endpoints**: `--require-complete` previously qualified a
  shorter observed interval (gaps counted only between found blocks).
  `coverage_endpoints` now requires `min==seg_lo && max==seg_hi`; missing
  requested blocks = incompleteness (strict exit 1, diagnostic emits a
  clean-but-incomplete projection). Regression: `--segment 1:3` over a
  2-block corpus fails on all modes' completion claims.
- **CHAIN coverage**: `chain_hashes.get(h)==None` silently skipped the
  selected-chain comparison. Now counted (`headers_chain_missing`) and
  gates `window_complete` — a CHAIN list shortened to genesis leaves the
  base binding satisfied but is correctly incomplete.
- **State oracle**: the flat-boundary fixture now parses the exported
  canonical and compares complete records (txid/vout/value/script/
  height/coinbase) — not merely the survivor count — and asserts the
  same-block-spent output is absent.

Receipt fixes: `run-manifest.json` gains `wall_s_total` measured after
all input/output hashing (the JSON `wall_s` still excludes it — labeled
as such); `guard_run.sh` receipts now record host loadavg + MemAvailable
at start/end plus an outer wall second count; `comparison-receipt.json`
in the corpus dir records the real `cmp -s` result (exit 0, byte-
identical), donor/converter/export sha256s and argv. The CI workflow now
runs `tools/test_window_join_exec.py` on the release binary and prints
its sha256 — the 114-check runner output is preserved at
`corpus-454k/exec-regressions.txt`.

Metric corrections from the audit: recorded `rss_hwm_bytes` is
7,057,620,992 B = **6,731 MiB** (the earlier "7,057 MiB" figure was a
units error); the cgroup sampled peak is a separate 8,191 MiB against an
8,192 MiB cap. Script throughput ≈ 1,303,682/31.77 ≈ **41,041 verified
inputs/s** — verified inputs, not signature attempts, and not a
dedicated-capacity figure (competing load unrecorded on that run).

Suite: **114 executable checks** — the followup audit's six controls
(endpoint gap ×3 modes, short-CHAIN ×3 modes) plus the byte-exact oracle.

## 2026-09-27d — capacity measurements (dedicated window + era scaling)

- Dedicated 454k rerun on clean `9986ea5` build: identical export
  `865d32cf…`, all flags true, outer wall 98 s (internal 83.1 + ~15 s
  receipt hashing — `wall_s_total` now records it), process RSS
  6,729 MiB, cgroup peak 10,239 MiB.
- Six era slices (232k–956k; taproot era from the Core pruned tail,
  xor-decoded): verified-inputs/s 81k→39.5k with density 770→7,738
  inputs/blk. Zero invalidity anywhere. Full table + full-IBD model in
  `docs/IBD_CAPACITY_MEASUREMENTS_2026-09-27.md` → script verification
  ≈24 h dominates; ~28–30 h pipeline total; one-hour objective needs
  ~25–30× (batch crypto × more cores × overlap) and ≥140 MB/s
  acquisition.
- Fixed: `window_join` panicked on an empty `--segment` selection → now
  clean exit 2 with a regression control.
- Segwit-era block bodies absent from both datadirs — flagged as the
  model's unmeasured segment.

## 2026-09-27e — structural overlap + measured optimization ledger

**Code (this commit):** `window_join` parallel prologue — boundary
snapshot load, boundary/header file digests, and `HeaderTree` build now
start at t=0 as scoped threads overlapping corpus read+parse; the corpus
sha256 runs concurrent with decode. `join_window` shards resolution by
`txid[0]&7` across 8 workers (violation ordering and first-missing
semantics preserved). Boundary-spec conflict check chunked across 4
threads. Manifest digests reuse bytes already hashed (no ~5.5 GB re-read
tail). Materialize+export remain serial after scripts: the earlier
overlap attempt was **measured harmful** — verify CPU 200.9→523.4 s and
wall 91.9 s vs 83.7 s quiet baseline; the ~3.6 GB stream starves the
ecmult table footprint on the single memory channel. Comment left in
`window_join.rs` with the receipt.

**A/B under matched load ~8–13** (alternating `3198d50` baseline binary
vs candidate, 4 pairs, identical inputs, distinct output paths):

| round | base JSON wall | cand JSON wall | base outer | cand outer |
|---|---:|---:|---:|---:|
| 1 | 89.3 | 94.7 | 104 | 97 |
| 2 | 125.0 | 78.7 | 139 | 79 |
| 3 | 91.3 | 94.7 | 114 | 97 |
| 4 | 127.1 | 108.4 | 142 | 109 |
| med | **108.2** | **94.7** | **126.5** | **97** |

Median JSON wall −12.5% (~1.14×); outer wall −23% (~1.30×). Candidate
more consistent under contention (79–109 vs 104–142). All runs
`window_complete`, identical export sha. **Not 2×**: this window's floor
is ~200 CPU-s of individual ECDSA verifies (~26 s wall at 8 workers);
the overlappable non-crypto tail was ~45 s, now partially hidden.
Receipts: `run-manifest-{a-baseline,b-overlap}{1..4}.json` +
window-manifest counterparts under `corpus-454k/`.

**Optimization ledger — exhaustive, mostly measured:**

- Batch ECDSA: impossible without nonce-point R; computing R is the
  verify itself (parity-cube: lift_x gives 2^N ambiguity, no monotone
  bracket — Waddle-style corner coverage degenerates to enumeration).
  The earlier 34% prototype was advice-dependent; local advice costs the
  verification.
- Schnorr batch: advice-free, real — but zero Schnorr calls below
  709632.
- libsecp internals already optimal where it matters: projective
  x-compare (`gej_eq_x_var`, no final inversion), `scalar_inverse_var`,
  batched inversion of per-pubkey Strauss tables, GLV. Field impl =
  `5x52_int128` (upstream removed x86 asm as equal).
- `ECMULT_WINDOW_SIZE` sweep {15,12,10,8} ×8 threads vs vendored source:
  medians 27.8k/28.4k/—/23.2k sig/s — noise-overlapped, **no win**.
- **AVX2 4-lane field mul probe** (10×26-limb `fe_mul` faithful port,
  differential-verified vs scalar on randoms): measured **~1.2×/mul**
  (42.8 ns vs 51.5 ns scalar). `vpmuludq` 32-bit lanes are the wrong
  shape for a 64-bit-limb prime; the real lane trick needs AVX-512 IFMA
  (`vpmadd52luq`) which the i3-N305 lacks. Dead by measurement.
- Remaining live micro-tranche (~10% verify): pubkey-parse/Q-table cache
  on repeated keys (~50% hit), fused parse+verify FFI.
- Rescope note: stacking everything lands ≈1.5× → ~19–21 h full IBD on
  this box; sub-hour requires assumevalid (policy) or IFMA-class silicon
  / many cores (hardware) — measured conclusion, receipts above.

Suite: all 115 executable checks pass on this tree; `build_rev` records
`+dirty` where appropriate.

## 2026-09-27f — microarchitectural drill-down: the register-residency unlock

Full byte/cycle-level characterization of the ECDSA verify bottleneck on
the i3-N305 (8×Gracemont E-cores, no HT, 6MB L3, 2MB L2/4c cluster,
single-channel DDR5, AVX2+BMI2+ADX, no AVX-512/IFMA).

**Structural decomposition (vendored secp256k1-sys 0.10.1, field_5x52_int128,
ECMULT_WINDOW_SIZE=15):** verify ≈ 86µs = ~11µs pubkey parse (X-decompress,
now partially cached: PK_CACHE_HIT measured 30.6% on real window) + ~3.5µs
scalar_inverse_var + ~72µs ecmult_strauss_wnaf = GLV-split 4×~128-bit
wnaf halves → ~129 chained gej_doubles (~340ns) + ~58 adds (~600ns) +
8-entry pre_a build. Field-mul: 25 mulx + ~30 adcx/adox carry ops, ~60µops,
critical path ~120cyc ≈ 43.5ns serial-dep vs 12.2ns indep — the mulx+flag
relay is latency-bound; ~80% of each mul is carry latency not throughput.

**Dead ends, all measured (not argued):**
- ecmult window sweep {15,12,10,8} ×8 threads: medians 27.8k/28.4k/—/23.2k
  sig/s — noise overlap, no win.
- AVX2 4-lane fe_mul (10×26-limb, correct mod-p arithmetic): 42.8-45.5ns/mul
  vs scalar 43.5-52ns → **~1.2×**. vpmuludq 32-bit lanes wrong shape; the
  lane-parallel prime-field trick needs AVX-512-IFMA vpmadd52, absent.
- FP/FMA 4-lane fe_mul (10×26 as f64, TwoProdFMA): measured **0.44×**
  (98.8ns/mul) — accumulator accumulation creates a new serial chain;
  product-count tax (100 vs 25) cancels FMA throughput. vfmadd ymm
  throughput measured 1.51 vec-ops/cyc = 6.0 lane-fma/cyc vs imul 1.8/cyc.
- 4× independent full ecdsa_verify: 92.4µs/verify — wnaf-driven branches
  prevent OoO overlap across call boundaries.
- 4× indep gej_double/gej_add calls: ~1.0-1.1× — investigated aliasing
  (separate named gej locals: same result, ruled out) and branch fusion
  (identical instruction stream after inlining — parity by construction).
- Fused gej_double4 (per-lane locals, interleaved ops): 0.98× — same
  stream as 4 inlined calls.
- Batch ECDSA: mathematically dead (needs nonce point R; computing R IS
  the verify). Schnorr batch real but absent pre-709632.

**THE UNLOCK — measured positive result:**
- Op-mix probes: 4 independent muls interleaved with sqr/add/negate still
  pipeline at ~11.6ns/mul (vs 43.5 serial) — the point-op op mix was never
  the blocker.
- gej_double formula re-emitted on NAMED LOCAL fe vars (register-resident,
  no pointer/struct access): **1× = 305.5ns/op, 4× interleaved = 149.7ns/op
  → 2.04× measured.** The pointer-based gej* API's memory traffic
  (~10×40B load/store per op, store→load forwarding ~5cyc each) was the
  hidden serial resource saturating the latency budget the OoO needed.
- ROB capacity ≈ ~4-5 concurrent fe_mul chains (~250µops) — the ILP
  ceiling on Gracemont, consistent with all measurements.

**Design that follows — merged-4 `verify4`:**
- 4 signatures' ladders run in one instruction stream; all gej state in
  locals (never memory); per-step fused dbl×4 + per-lane predicated adds.
- Bonus: the 4 lanes' pre_a global-Z inversions batch into ONE inversion
  (Montgomery trick); scalar inverses also batchable.
- Bound: doubles ~2×, adds ~1.5-2×, batched inversion ~-3µs/verify →
  verify ~86→~45-55µs → ~1.6-1.9× verify → ~1.8-2.3× window stacked with
  structure+pkcache. Multi-day build + full differential testing vs
  libsecp required — new consensus-path crypto, scalar fallback retained.

## 2026-09-27g — merged-4 ecmult prototype: the unlock is real but capped

Harnesses archived in experiments/code/:
- dbl4_locals_bench.c    — THE unlock: gej_double formula on named-local fe
  vars (register-resident, no pointer traffic): 1x=305.5ns, 4x=149.7ns/dbl
  → 2.04x. Pointer-based gej* API memory traffic was the hidden serial
  resource.
- add4v.c-equivalent inline in ecmult4_merged_bench.c — var-time add on
  locals: 1x=605.5 → 4x=447.8ns → 1.35x. (Complete-formula Brier-Joye add
  measured 0.95x — deeper DAG defeats the ROB; validation doesn't need CT.)
- ecmult4_merged_bench.c — full merged-4 strauss ladder (4 lanes' gej in
  named locals, fused dbl x4, per-lane predicated adds, correct shared-Z
  globalz + beta-aux ordering): differential-verified correct vs scalar
  ecmult on all lanes. MEASURED: 101.3us vs 120.7us scalar x4 → **1.19x**.
  The composite is capped by the adds' deep DAGs (~750uops/op >> 250-entry
  ROB) + sparse-branch stream — exactly the DAG-depth bound predicted.
- fma_tput_bench.c — vfmadd ymm = 1.51 vec-ops/cyc = 6.0 lane-fma/cyc vs
  scalar imul 1.8/cyc — FP has 3.3x the per-cycle multiply throughput BUT
  FP field-mul probe measured 0.44x (accumulator serial chains + 4x
  product count of 10x26 vs 5x52 limbs).
- ge_ilp_bench.c — 4x indep gej_double/add calls = ~1.0-1.1x; alias-free
  named locals same result; the calls emit the same instruction stream
  after inlining → parity by construction.
- verify_ilp_bench.c — 4x indep ecdsa_verify = 92.4us/call vs 86.5 serial
  — wnaf-branch dispatch prevents cross-call overlap.
- femul4_avx2_bench.c — correct 4-lane 10x26-limb AVX2 field mul:
  ~1.13-1.22x — vpmuludq 32-bit lanes wrong shape; needs AVX-512-IFMA
  (absent on i3-N305).

**Where the merged-4 bound lands**: ecmult ~1.19x → verify ~1.15x →
window ~1.08x on this era. NOT sufficient alone to justify a
consensus-path rewrite.

**The remaining unexplored axis — hand-interleaved assembly**: C cannot
express interleaving the four lanes at single-instruction granularity;
the OoO was expected to perform that reorder but measured shows it does
not through the adds' deep DAGs. Hand-scheduled round-robin emission of
the four lanes' mulx/carry ops could approach the proven 12ns/mul
indep-chain rate (vs ~43ns serial) — ceiling ~1.5-1.8x on verify. Cost:
multi-week consensus-critical asm + full differential harness. Deferred
pending decision; C merged-4 result stands as the baseline to beat.

## 2026-09-27h — independent crypto-ledger source and assembly audit

The saved sources do **not** support the ceiling or all of the measurements
in the preceding entries. Review and proposed experiments:
`experiments/2026-09-27-crypto-ledger-review.md`. Source hashes, compiler argv,
generated FMA-loop assembly and correctness evidence:
`experiments/results/2026-09-27-crypto-ledger-review/`.

- Archived AVX2 field-mul correctness section: **15,004 mismatches / 16,000
  lanes**, exit 1 under `guard_run.sh --max 512 --reserve 4096` and a
  20-second timeout. Only the timing section was removed. The 260-to-256-bit
  conversion drops top bits without folding them modulo p; the first error
  is exactly `7 * (2^32 + 977)`. This probe does not rule out AVX2.
- Merged-4's 1.19x comparison times scalar setup but excludes candidate
  setup, then mutates a table coordinate without its associated data.
  The initial four comparisons do not validate the timed workload. Its
  added dbl-only loop keeps infinity set and returns before arithmetic.
- GCC 15.2 emits one FMA dependency chain and two integer multiply chains
  from `fma_tput_bench.c`, while its numerators charge eight of each. The
  reported throughput comparison is invalid for this generated program.
- The pinned global-Z routine has no field inversion. The earlier 512-record
  census already records zero field inversions in verification; magnitude
  metadata is absent in non-VERIFY builds. Those proposed savings are not
  available. Intel documents a Gracemont dependency between ADCX and ADOX,
  relevant to the proposed assembly schedule.

This was a bounded correctness/compiler audit, not a new speed benchmark.
No production change or new speedup is claimed. The review recommends testing
exact 52-bit-limb FMA, operation-level schedules across independent jobs, and
amortized affine arithmetic, with complete matched work and separate verdicts.

## 2026-09-28 — 4x64 hand-asm mul + matched merged-4 correction

**fe_mul_4x64_asm (experiments/code/fe_mul_4x64_asm.S)** — row-major
BMI2/ADX 4x64 field mul, CORRECT (10K differential cases + edges; scheme
verified on 100K in rowmajor_sim.py). ~184 instructions. MEASURED under
load-9 machine, pinned core: serial ~58-70ns vs libsecp 5x52 ~50-56ns,
indep ~50-55 vs ~46-53 — PARITY-TO-WORSE, not faster. Consistent with
Intel opt-manual §4.1.8.8 (Gracemont tracks arith flags together —
adcx/adox are NOT independent chains there). The product-count win
(16 vs 25) was eaten by ~30-deep dual flag chains + ~35 bookkeeping ops.
**Conclusion: asm 4x64 mul does not beat C 5x52 on Gracemont.**

**MATCHED merged-4 re-measurement (ecmult4_matched_bench.c)** — fixed
audit item 2 (both sides pay identical work: prep+tables+globalz+beta+
ladder; same scalar perturbation; all outputs consumed; dbl sub-bench
uses valid non-infinity points):
- dbl seq-4 vs fused-4: **0.99x** — the earlier "2.04x locals unlock"
  was entirely the inf=1 early-return artifact (empty loop measured).
- merged-4 ecmult matched: **1.01x** — the earlier "1.19x" was the
  setup-exclusion artifact (candidate skipped prep/tables/beta that
  scalar paid inside ecmult).

**Both headline numbers were measurement artifacts. The merged-4
direction is DEAD at ~1.0x.** OoO already extracts all parallelism the
same-formula-interleave stream can offer. Named-locals "register
residency" was illusory — 12 fe = 60 limbs can't fit in 16 GPRs anyway.

**Surviving directions (per the audit's recommended designs):**
1. Exact wide-limb FMA (5x52 SIMD, Emmart-Zheng-Weems ARITH'18 style):
   25 product pairs, exact split via round+FMA-residual. AVX2 NOT ruled
   out — earlier rejection used a buggy 10x26 kernel (15K/16K mismatch).
2. Tiled ready-op scheduling across independent verifies (tile 4-32) —
   different from merged-4: dispatch a QUEUE of ready field ops rather
   than whole formulas per lane.
3. Affine batch coords + Montgomery inversion amortization: amortized
   add ~(5-3/B)M+S+I/B vs Jacobian 8M+3S (~2x fewer units at B=16-32);
   affine doubling worse unless sqr cheap — mixed design, needs bench.
4. Repeat-key comb tables (~30% repeat keys): precomputed spaced-power
   combos beat 129-tower+128-adds.

**Artifacts:** fe_mul_4x64_asm.S (correct, ~parity), fe_mul_4x64_bench.c,
fe_mul_4x64_test.c, rowmajor_sim.py, ecmult4_matched_bench.c (corrected
harness — the standard for future comparisons).

**CRITICAL follow-up (same day):** audit-grade ILP probe (ilp_verify.c —
consumed outputs, varied lanes, distinct b per lane):
- serial fe_mul: 42.6ns ; indep4: 39.0ns ; indep4B: 41.9ns
- **The "3.57x independent-chain ILP" premise is FALSE.** Four independent
  mul chains run at ~serial rate → the shared serial resource is NOT the
  ROB — it is the CARRY-FLAG machinery itself. All adc/adcx/adox across
  all lanes serialize on one flag-tracking structure (consistent with
  Gracemont §4.1.8.8). Math: ~35-40 flag-hops/mul at ~1/cyc ≈ ~40ns —
  matches both serial and indep rates.

**This reframes the whole problem: the ONLY way to speed up field ops on
Gracemont is to stop using carry flags.** Flag-free datapaths:
- SIMD vpmuludq: 32x32->64 — can't hold 52-bit limbs (needs AVX512-IFMA,
  absent); 10x26 repr quadruples product count — measured dead.
- **FMA exact-split (Emmart-Zheng-Weems ARITH'18): 52-bit limbs fit the
  53-bit double mantissa; product splits exactly via round+FMA residual;
  carries via vpsrlq/vpand — ZERO flag ops. 25 pairs, ~50 FMA-class ops,
  FMA tput ~2/cyc → est ~9-15ns/mul if flag theory holds.** THE remaining
  crypto lever with a mechanism that escapes the measured bottleneck.
  (Earlier FP probe used wrong 10x26 repr — the audit's point exactly.)
- data-register carries in scalar: shrd/add-based 5x52 still uses adds
  (flag ops) — not an escape.

Next: exact-split FMA 5x52 fe_mul probe (4 lanes, ymm), correctness vs
libsecp, measure serial+interleaved.

## 2026-09-28b — BREAKTHROUGH: EZW-style FMA field mul works

**fe_mul4_ezw (ezw2.c, experiments/code/fe_mul4_ezw.c)** — fused-4-lane
5x52 field mul using the Emmart-Zheng-Weems ARITH'18 RZ-FMA trick:
- hi = fma_rz(a,b,2^104): lands product into [2^104,2^105) binade ->
  bits(hi) - bits(2^104) = p>>52 AS INT BIT-PATTERN (no conversion!)
- ad = (2^104+2^52) - hi; lo = fma(a,b,ad): -> bits(lo)-bits(2^52) =
  p mod 2^52. Requires FE_TOWARDZERO (ldmxcsr once per kernel; the
  round-nearest signed-residual path can't hold a single binade).
- Column sums accumulate biased bit-patterns via vpaddq; init each
  column to -nterms*bias (mod-2^64 wraparound exact).
- Carry-resolve + mod-p fold ENTIRELY in SIMD (vpsrlq/vpand/vpaddq;
  the out*16C fold uses the same RZ-FMA hi/lo split, C=(2^32+977)).
- Requires AVX2+FMA (N305 yes); correctness vs libsecp fe_mul:
  **200K random cases all lanes pass.**

MEASURED (pinned core, load ~9 machine):
- serial chain: ~115ns/group = ~29ns/mul-equiv
- independent: **~28ns/group = ~7.1ns/mul-equiv vs ~40ns flag-bound
  libsecp — ~5.6x throughput**
- libsecp 5x52 fe_mul: ~40-43ns serial AND ~39-43ns "independent"
  (flag-resource is the shared serial bottleneck — confirmed).

INTERPRETATION: this is the first datapath that escapes the flag
bottleneck. In a merged-4 ecmult each DAG-level has ~4 independent
muls — fused-4 processes them at ~29ns latency-bound to ~7ns
throughput-bound per mul-equivalent vs ~40ns. Combined with a fused
ladder (fe_sqr via symmetric products ~15% cheaper, fe_add/negate
trivial in int lanes), the ecmult mass plausibly lands ~2-3x.

OPEN ITEMS: register pressure (45 live ymm > 16) — needs scheduling/
blocking; chain latency 115ns has spill overhead; fold's residual
carry iterations bounded at 2 (verified sufficient on 200K but needs
proof/exhaustive bound check); MXCSR RZ mode must bracket each kernel
(ldmxcsr ~10-20cyc, amortize over whole point-op); aliasing/output
semantics for in-place ops. fe_sqr4 variant next (half the products).

## 2026-09-28c — fused-4 dbl4 correct; latency-bound diagnosis

- fe_sqr4_ezw: correct 100K (off-diag via doubled bit-accumulation,
  diag via separate accs; noff/ndiag bias tables).
- gej4_double (fused-4 point double): correct on all coords, all lanes,
  2000 random cases vs libsecp gej_double.
- SIMD helpers needed for point formulas: fe4_add/neg/mul_int/half —
  each emits normalized <2^52 limbs (product binade constraint:
  operands must be <2^52 or hi=fma(p,2^104) overflows its binade).
  fe4_neg uses 4p-a with explicit SIMD borrow chain; fe4_half adds p if
  odd via lane-select, then propagates the carry and >>1s across limbs.
- fe_mul4 tail bug fixed: F[5] (weight 2^260) folds by *16C into limbs
  0,1 — NOT into limb4 (2^260 ≡ 16C mod p directly at weight 2^0).
- TIMING (pinned, noisy machine): fused dbl4 serial chain ~920ns/dbl4
  = ~230ns/dbl-equiv vs scalar ~343ns = **1.48x**. Interleaving TWO
  independent dbl4 streams (8 sigs) gains ~0% — the fused ops are
  LATENCY-bound (~115ns each), not ROB/scheduling-bound.
- Root cause of latency: ~720 emitted insns (~100 spill refs) — 10 acc
  + 10 operand + temps > 16 ymm. Merged-acc variant (single column
  accumulator absorbing both lo-bits and hi-bits via combined bias
  init) verified correct on 200K — cuts accumulator regs ~45%->~20.
- NEXT LEVERS: (a) kernel latency — fewer live ymm (mem accumulators
  or column-streaming), shorter resolve/fold tail (~90 ops mostly
  serial), maybe merge norm into ops; (b) if latency ~60ns: dbl4 ~2.7x
  scalar, ecmult4 ~2.5-3x.
- CEILING model now: verify4 = ~350 fused ops ~100-115ns = ~40us vs
  ~86us scalar = ~2.2x ceiling at CURRENT latency; ~60ns -> ~4x.
  This is the crypto mass only (~50-60% of IBD wall).

## 2026-09-28d — radical-redesign survey + fused add/ladder-cadence measured

Prompt: "you're not thinking radically enough" → surveyed structurally
different architectures before more kernel tuning.

**Established dead/small (checked against prior artifacts):**
- Batch-ECDSA on on-chain sigs: math-level dead standalone — R parity is
  unknowable without computing R' (subset-sum over 2^N). Confirms
  [feasibility doc](2026-09-23-ecdsa-batch-feasibility.md): only
  summation-polynomial (~2× @ batch ≤9, novel crypto) or R-advice works.
- R-advice batch already measured: 1.82–2.27× CPU kernel-side; ~17–23% CPU
  in the real 8-worker pipeline ([parallel-replay](2026-09-24-ecdsa-parallel-replay.md)).
  NOT standalone: advice production ≈ verification cost; requires external
  helper data (peer sidecar). Fits user's experimental-mode plan.
- Schnorr MSM batch: clean (R in sig) but Schnorr ≈ **8% of sig mass**
  at 956k census → ~1–2% end-to-end. Deprioritized.
- Node already runs 8-way script-pool parallelism — per-core kernel gains
  stack multiplicatively with it.

**New measurements (all differential-validated):**
- fe_mul4 v3 (memory-resident accs): correct 200K, but worse — store→load
  acc chains serialize. Register accs confirmed better.
- Dead-iteration cut (F[5]-drain was folding zeros on iters 2–3):
  dbl4 serial 877→**687ns** (~172ns/dbl-equiv), ladder mix **1.71×**.
- gej4_add_ge4 built (8 mul + 3 sqr + 11 add, affine lane operand) —
  fused 7dbl+1add cadence: 5879ns/8-step/4-lanes = **1.71× vs scalar**.
- v4 lag-1 column-order (2 live accs): correct 200K, ~parity latency —
  serial path is intrinsic, not spill-dominated.
- Latency split: products+resolve = **60ns**, tail = **~53ns** of the
  ~113ns fused-mul latency. Interleaved folds regressed.

**Ceiling model (unchanged, sharper):** latency-bound serial ladder ≈
~1.7× now, ~2–3× with kernel/asm work. The one remaining big standalone
structure is a **static op-schedule engine** (comb-based mul → fixed
dependency graph → emitted op-list, multi-stream interleave) — targets
the ~7µs/sig port-throughput bound vs ~30µs serial-latency bound.
Untested premise: whether sub-256-uop fused ops can overlap in the
rename window (interleave-2 measured ~0% at 700-insn ops).

Artifacts: /tmp/fma4/{dbl4.c,ezw_body.c,v4.inc,mul4_v4.c,lat_probe.c}
(working copies; canonical copies archived under experiments/code/).

## 2026-09-28e — SP-batch derivation: it collapses to the advice scheme

Derived the summation-polynomial batch construction from first
principles (paper PDF unreachable — network). Result: for unmodified
ECDSA, f3 "exists-a-lift" is exactly ECDSA's sign-agnostic x-check —
but realizing the batch still requires *lifting* each r_i to a curve
point = one mod-p sqrt per signature (~380 field ops ≈ ~28% of a
verify). Fused-4 cost model: MSM saves ~50%, lifts cost ~35% →
**~1.2× standalone — marginal**. The paper's ~2x@t≤9 comes from
symbolic resultant elimination (exponential in t, novel-crypto risk).

KEY STRUCTURAL FINDING: SP-batch ≡ advice-batch. The existential lift
is precisely what R-advice provides for free. The missing bit per
signature (which of {r, r+n} × ±y) is information not derivable
cheaply from the signature — the ~2^-128-equivalent of ~2 bits. This
is the first-principles reason every batch path converges on needing
external data: not a missing trick, missing information.

Closed cheaply today: sha2 0.11 already runtime-dispatches SHA-NI
(confirmed in vendored source, sigchecker→sha2 path). iGPU killed on
arithmetic (32 EUs ≈ ~2-3 cores int throughput ≈ ~5%). perf locked
(paranoid=4) — port analysis done analytically: fused-mul port floor
~40ns vs measured ~95ns → latency/spill-bound with real ~2× headroom.

## 2026-09-28f — session close: handoff ledger written

Full measured ledger at [2026-09-28-crypto-deep-drill-ledger.md]
(2026-09-28-crypto-deep-drill-ledger.md): every verified artifact,
every invalidated measurement, mechanism findings (flag serialization,
op-size-vs-ROB, info-boundedness of batch ECDSA), probed-thin leads
(CSA/interleaved-SHA-NI/affine/cache), and ranked next investigations.
Top recommendations: interleaved SHA-NI sighash (cheapest real win),
fused-4 kernel scheduling to port floor (biggest verified headroom),
repeat-key census + tower cache, verify4 composite for the honest
end-to-end number. 46 code artifacts in experiments/code/.

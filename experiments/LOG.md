# Experiment log

Running record of every experiment tried — adopted, rejected, blocked,
or inconclusive. One line per attempt; details live in the dated docs.
A "failed" or "inconclusive" row is a result, not a gap — write it down.

| # | Date | Experiment | Hypothesis | Verdict | Key numbers | Doc |
|---|------|-----------|------------|---------|-------------|-----|
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
| 61 | 09-24 | Per-block verification receipts | Can every connect produce machine-checkable evidence? | **adopted — queue #5 core shipped** | `connect_block_full` returns a `BlockReceipt` per connect: script_flags enforced, fees/sigops, checks queued vs verified-cache skips, spent/created counts, wall_ns, and `delta_commitment` — SHA-256 over the exact UTXO transition (per-tx: txid, spends, creates, block order), replayable by construction. Journal ring (2016) in Chainstate covers all three real connect paths — tip extension, reorg `simulate_branch` (the sim IS the connect), and assumeutxo background replay. `getblockreceipts`/`getblockreceipt` RPCs. 4 tests: field correctness, replay determinism, delta sensitivity, both-sides-of-reorg journaling. A standalone replay-verifier tool + bundle export stays open. | — |
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

2. **Verified-artifact distribution format.** Replay + parallel-verify
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

7. **Stem-phase tx relay on top of recon.** Recon rounds are already
   the epidemic "fluff"; add a private stem path for N hops before the
   tx joins the reconciliation pool. Honest limits: propagation
   latency, known Dandelion deanonymization attacks.

8. **Shadow-ruleset observatory.** Read-only evaluation of every block
   under alternate rulesets (Knots policy, proposed softforks) — a
   continuous consensus-drift monitor. Must never gate acceptance.

9. **Dual-engine lockstep mode.** Two independent validation paths,
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

14. ~~**Per-peer adversarial accounting.**~~ **done — #56 (contract published; three gap rows named open).** Formal per-peer budgets —
    bytes, CPU, memory, queue slots — as a *tested contract*: fuzz the
    boundaries, prove no hostile peer exceeds allocation under any
    input sequence.

15. ~~**Continuous self-audit.**~~ **done — #54 (stored-block integrity; UTXO-replay auditing open).** Background re-verification of random
    historical segments, forever — correctness as an ongoing property,
    catching disk rot and bitflips. Each pass appends receipt evidence.

16. ~~**Pinning oracle.**~~ **done — #46 + wallet-labeling.** Mempool watcher that detects pinning patterns
    against the operator's wallet transactions — descendant-limit
    saturation, RBF rule-3 pinning, parked conflicts — and reports it.
    The node tells you when you're under attack; nobody ships this.
    Real value for LN operators.

17. ~~**V2 traffic padding.**~~ **done — #47 (decoy injection; fixed-size cells still open).** The 2025 v2-transport analysis showed
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

29. **First-class watch-only wallet.** Descriptor/xpub import, balance
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

33. **Named observability surface.** Package existing per-peer
    claims-vs-served, timing, recon state as the documented
    event-stream API — literally Core issue #34901 ("block processing
    is a black box"), which we already satisfy.

34. **Evidence server.** Compact filters (shipped) + PoW fraud proofs
    + artifact bundles served to the operator's own light clients —
    your phone trusts your node.

22. **Self-eclipse field test.** Build the attack: attacker nodes that
    monopolize all our outbound slots in a lab topology. Hypothesis:
    detection signals (header stall, peer homogeneity, route
    uniformity) fire within bounded time. Kill condition: our own
    eclipse goes undetected — learn it now. Nobody publishes eclipse
    experiments on their own node; even a negative result is tooling.

23. **Pinning red-team.** (partial — #46 two attacks proven) Implement BIP-431's documented pinning
    attacks as tools (descendant-limit saturation, rule-3 pinning,
    package-limit pinning), run against our mempool on regtest.
    Hypothesis: oracle catches all documented classes with bounded
    false positives. Kill: pinning is indistinguishable from
    legitimate high-descendant usage — the signal isn't separable.

24. **Continuous dual-engine lockstep.** (fixture-scale proven — #50; live-shadow plumbing open) We already have two coins
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

28. **Adversarial live-wire suite.** Hostile peers at max rate —
    malformed messages, floods, slowloris — measure per-peer budgets
    hold under sustained attack. Kill: a hostile peer can starve
    honest peers — find the hole now.

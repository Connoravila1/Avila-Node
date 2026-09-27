**SWE-2 networking assignment: distinguish link limits from node architecture**

Read [the networking audit](IBD_NETWORK_ANALYSIS_2026-09-26.md) and retain
[the full-validation research requirements](IBD_RESEARCHER_WORK_ORDER_2026-09-26.md).
This adds networking work; it does not replace the offline census already in
progress. Codex performed source/configuration inspection and arithmetic,
not networking experiments. All source-derived performance opportunities need
measurement before a speedup claim.

**Ownership and target**

Use [the accepted product objective](IBD_PRODUCT_OBJECTIVE.md) as the completion
boundary and reference hardware/connection specification.

The live IBD agent retains daemon, peer-manager, scheduler, and chainstate
integration ownership. The researcher should finish the current census and
prepare isolated transport/encoding experiments. Coordinate an explicit file
handoff before editing shared live-path files. Do not restart or retune the
running node for these experiments, open its writable chainstate, or run
saturating host/network tests concurrently and label the result clean capacity.

Use a separate checkout/process/datadir and controlled resource window for
load measurements. Preserve other agents' work. No consensus checks may be
disabled in an end-to-end result; a diagnostic acquisition-only result must
be labeled separately. Use only Bitcoin data and Bitcoin peers.

The target is first launch with no historical corpus to fully checked usable
chainstate. Acquisition, helpers, reconstruction, state, all script tails, and
the completion checkpoint count. Record the benchmark tip plus handling of
new arrivals. The assumed raw 768 GB needs 1.707 Gbit/s of payload to arrive in
one hour. At measured 940 Mbit/s payload the entire transmitted application
representation must fit below 423 GB, including helpers. Replace assumptions
with census data, and leave room for startup/final drain.

**N0 — Obtain interpretable measurements before changing transport**

Record revision/diff, compiler/features, hardware, power mode, competing load,
link topology, transport/privacy settings, peer software/coverage, corpus
range/hash, cache state, and validation flags. Record actual measured goodput,
not the ISP plan or Wi-Fi link label. Avoid collecting credentials or publishing
peer identifiers unnecessarily.

Instrument the following boundaries with monotonic timestamps and counters:

- Request selected, frame queued, request bytes accepted by socket, first body
  bytes, complete body, decode complete, validation starts, fully checked tip.
- Per-peer last socket-service time and longest service gap; time in poll,
  parse/authentication, dispatch, disk work, and request replenishment.
- Actual thread/process CPU separately from elapsed wall time and waiting.
- Queued output, successful socket read/write bytes, transport/padding/helper
  bytes, unique needed blocks, duplicate/late blocks, and rejected data.
- In-flight copies and estimated bytes; raw/decoded/staged memory high-water
  marks; bytes remaining when a timeout fires; local backlog at that moment.
- RTT, delivery/retransmission and receive-window information where the socket
  interface exposes it. Receiver-side observations do not reveal every remote
  sender constraint; instrument the sender in controlled tests.

`PeerSession::bytes_sent` currently counts queued frames and omits separately
appended padding/decoys. Correct the semantics or add distinct counters. Socket
write completion is kernel acceptance, not remote delivery or interface bytes.
Likewise, `PeerManager`'s dispatch CPU counter currently measures wall time.

Use a controlled Bitcoin-serving endpoint to compare acquisition into a bounded
sink, normal staging, and full validation for the same blocks. Acquisition-only
is a diagnostic, never the reported full-IBD result. Add a controlled ordinary
bulk download to distinguish a slow Bitcoin-serving path from slow connectivity.
Compare 1/2/4/8 peers only where useful, holding aggregate serving capacity and
corpus constant. Do not infer a transport win from a faster unrelated server.

Deliver a bottleneck account: receiver/link constrained, sender constrained,
request/window constrained, local CPU/storage constrained, or mixed; include
uncertainty and enough raw data to reproduce the conclusion.

**N1 — Reproduce framing behavior and bound socket service**

First reproduce the source-derived v1 edge case: a legal maximum payload frame
followed by another legal frame in one decoder buffer. Test fragmented and
coalesced delivery, near-limit lengths, malformed lengths, checksum failure,
and sustained total buffering. The existing `over_buffered()` check examines
total bytes before consuming a frame. Fix per-frame enforcement together with
an explicit total-memory bound. Do this before enlarging reads.

Evaluate incremental header parsing, reusable buffers, larger bounded reads,
and a per-peer byte/time/event service budget. Avoid allocating/reparsing the
same header throughout a partial body. Verify v1 and BIP324 separately.
Preserve transport authentication, configured privacy behavior, and fallback.

The live-path owner should then evaluate separating readiness service from
synchronous validation, serving reads, replay, and flush work. Keep ordered
state ownership and the checked frontier explicit. Test saturated ingress,
slow validation, slow storage, a continuously readable peer, disconnects, and
bounded recovery after pressure. Report read-gap percentiles, goodput, memory,
kernel/application CPU, and total fully checked progress. A throughput gain
that grows memory without bound does not pass.

**N2 — Make windows and timeouts account for work and progress**

Measure when the 16-block cap actually binds. Sixteen 2 MB blocks can already
fill many ordinary paths; sixteen tiny historical blocks may not. Estimate
per-peer byte windows from throughput, RTT, serving/refill delay, and staging
capacity, with a global memory limit and peer diversity constraints.

Separate unsent local requests, remote waiting, active body delivery, and
local processing delay. Replace indiscriminate request-age interpretations
with bounded progress-aware policies. Do not let trivial byte dribbles hold
reservations forever. Test slow but progressing large blocks and a truly stalled
frontier, including local flush/CPU pauses.

Account for originals and hedged copies after reservation release: ordinary
Bitcoin block delivery has no per-request cancellation that erases already
queued traffic. Measure useful unique bytes per received byte, duplicate
cost, completion tails, and peak memory. Do not call more socket throughput
a win when fully checked progress is unchanged.

**N3 — Implement and test BIP152 interoperability for the live tip**

The inspected revision only has compact-block names in BIP324's command table
and an inventory tag. It lacks message decoding, negotiation, reconstruction,
and missing-transaction handlers; RPC high-bandwidth flags are hardcoded false.

Implement the applicable witness-aware exchange from BIP152 with real Bitcoin
Core interoperability. Cover negotiation, both announcement modes, short-ID
collisions, prefills/index bounds, partial mempool coverage, response validation,
fallback to full blocks, disconnects, reorgs, and bounded adversarial input.
Reconstruction never replaces full block validation. Publish an authoritative
tip or corresponding mempool effects only through the checked-state boundary.

Measure complete-block availability and checked-tip latency for controlled
100%, 95%, and low transaction coverage, followed by real-mainnet observations.
Record actual missing bytes as well as transaction counts. Compare both with
Avila's baseline and a specified Core version under matched conditions.
Include loaded CPU, background serving, constrained upload, RTT/loss variation,
and both median and tail results. Use real connections, not just codec fixtures.
Do not use miner timestamps as precise propagation timestamps.

This is the first live-relay task before proposing a custom FEC/UDP network.
A win over the current Avila baseline establishes progress; an advantage over
Core requires the separate matched comparison.

**N4 — Measure exact historical encoding and independent acquisition**

Use the existing mainnet census to choose representative eras and eventually
the complete pinned corpus. Start with original block objects over an optional
source, then evaluate lossless domain encoding. Measure all metadata, escape
cases, dictionaries, proofs/advice, fetch overhead, decode CPU, temporary disk,
and reference dependencies. Helpers are not free or trusted.

Round-trip exactly to original bytes and verify transaction/block commitments
and all consensus checks. Include historical serialization oddities and correct
outpoint occurrence/provenance. Chunk manifests provide transport integrity,
not Bitcoin validity. Test corrupt/withheld chunks, resume, mixed sources, bounded
memory, and ordinary P2P fallback. Keep independent peers for chain discovery.

Report encoded bytes and fully validated completion together. Compare chunk
sizes only enough to resolve the compression/dependency/resume tradeoff. A
compression ratio that needs excessive laptop decode work can lose overall.
First report sample results as samples, then the coverage needed to support a
whole-history claim. A local Core datadir import is a separate dev-loop metric.

**N5 — Only pursue an additional transport where evidence identifies its benefit**

If missing-transaction repair or packet loss dominates live-block tails after
N3, evaluate congestion-controlled FEC or a specialized relay experiment with
explicit resource/integrity boundaries. FIBRE is Bitcoin-specific prior art.
Measure parity overhead and behavior under contention; do not infer bulk-IBD
gains from a one-block latency result.

If unrelated transfers block one another or source management warrants it,
compare an optional HTTP/3/QUIC corpus endpoint against the same TCP source and
objects. Account for endpoint support, CPU, encryption, retry/resume, and shared
link capacity. Do not redesign general Internet transport or silently change
the laptop's global networking configuration.

**Return to Codex**

Log executed experiments, including null results, in `experiments/LOG.md`.
Run `cargo test --release -p <affected-crate>` for relevant changes and real
connection tests for protocol behavior. Keep targeted correctness regressions
for the framing issue and protocol edge cases; do not add tests that merely
mirror a chosen buffer constant.

Return small reviewable changes, raw measurement files, exact reproduction
commands, the completion boundary, and a table distinguishing measured results,
extrapolations, and remaining hypotheses. Recommend the next stage from evidence.
Do not present proposed gains, unavailable hardware, or acquisition-only numbers
as an achieved first-launch full-validation result.

# First managed mainnet IBD observation — 2026-10-17

## Scope

This was the first live mainnet initial sync observation on the current
8 GiB i5-9300H laptop. The node used ordinary on-disk chainstate and
block validation with `--assumevalid=0`; no SwiftSync or Utreexo module
was active. It was an early-chain operations and restart check, not a
complete IBD, throughput comparison, or validation of modern-chain
coverage.

## Configuration

- 8 GiB i5-9300H laptop, SSD
- `prune=8192`, `dbcache=256`, redb cache 256 MiB, mempool 64 MiB
- 6 peers, 16 in-flight blocks
- managed service cgroup cap: 3072 MiB; swap disabled
- Mainnet, ordinary disk-backed full block validation, `--assumevalid=0`

## Observation

The managed node started at approximately 04:02 UTC. During startup and
peer synchronization it buffered heights in the 128,000–844,000 range
before sequential connection/validation advanced. The final CLI observation
reported 1,228 connected blocks and 38,782 headers. A cached status snapshot
reported 1,063 connected blocks; these are asynchronous observations from
different reporting paths, so the CLI result is recorded separately rather
than treating the cache as authoritative tip state.

A clean stop preserved height 718 with hash
`000000000992f083d79cdd428b664ce97105c57fdc63049371bfa98c28dbbc79`.
After a clean restart at approximately 04:09:45 UTC, the node resumed at
height 889 and the saved-height hash matched. Two clean restart proofs have
now passed; this note records the first proof's exact saved height and hash.
These checks demonstrate persisted state continuity and successful resumption,
not a complete IBD or correctness beyond the node's ordinary validation
checks.

The service was stopped cleanly at approximately 04:10 UTC to make room for
the GUI build, then sync continued. At a later status observation on 2026-10-17,
the node reported 27,784 connected blocks and 971,809 headers. The validation
report showed no AssumeValid checkpoint (`assume_valid_checkpoint: null`) and
`historical_scripts_required: true`; the CLI binary SHA-256 was
`4560d816cdce06f8406034ad669ff7f21a6bcab766acf8946aec58f2d05beff8`. This
remains partial IBD: no completion point or modern-chain coverage was reached,
and there is no speed or SwiftSync/Utreexo claim. The machine and memory cap
are recorded so later runs can be compared on the same resource profile.

## Resource guidance correction

`AGENTS.md` now records the host as an 8 GiB machine. `tools/guard_run.sh`
defaults to an 8192 MiB cap plus a 4096 MiB reserve, which is unsuitable for
this host. Heavy jobs must pass explicit cap and reserve values based on the
current `MemAvailable`; do not infer that the wrapper defaults fit.

## Adjacent test reliability note

The same validation cycle found a flaky BIP324 unit test: one 4096-byte read
could stop before the handshake terminator after receiving up to 4095 bytes of
random garbage. The test now fixes the initiator garbage at the maximum,
asserts that the complete handshake and version packet were consumed, and
then probes the oversized encrypted length. Six targeted BIP324 tests passed.
The full workspace pipeline subsequently passed with 1,138 tests passed, 5
ignored, and none failed; workspace Clippy, rustdoc with warnings denied, and
release CLI/GUI builds also passed. The 2,560 MiB guarded run peaked at
1,297 MiB and took 223 seconds. This test-harness correction does not change
protocol behavior.

## Later live-sync and GUI operational check

At 04:44:27 UTC the connected height was 45,000 with 971,810 headers. The
node still reported IBD, `assume_valid_checkpoint: null`, and
`historical_scripts_required: true`; this remains an incomplete early-chain
observation, not an IBD completion or speed result.

The attached GUI was checked against the live node at 760×600 and 1440×900:
block 170 showed both transaction rows and seven columns, and full txid copy
worked. The live console accepted a valid request and rejected a method outside
the allowlist; traffic and peer views were observed. Closing the GUI exited 0
and left the same daemon PID active, with connected height advancing from
40,815 to 40,835 during the check. `getblockinspect` for block 170 at limit 1
returned distinct rows for offsets 0 and 1 with stable `next_offset` values 1
and null. A header 100 blocks ahead of the checked tip was reported as
`header_only` with `fully_checked: false`.

GUI's 74 tests, Clippy, and release build passed under a 2,560 MiB cap (1,189
MiB peak, 55 s); a follow-up constant-txid change also passed Clippy and
release build (718 MiB peak, 29 s). The user service is enabled for login and
the desktop launcher was tested. These checks do not cover 100-item GUI paging,
zoom behavior, or screen-reader behavior; those remain unverified.

## Later managed IBD status and restart check

At a later observation, the managed node was still performing ordinary
full-script validation; IBD is incomplete. Its validation policy continued to
report `assume_valid_checkpoint: null` and
`historical_scripts_required: true`. The CLI binary used for this check had
SHA-256 prefix `84aa111...`. A clean restart resumed from the saved state at
height 118,211 and advanced to 118,230; this is a continuity/restart check,
not evidence of completion or modern-chain coverage. The managed startup-stop
wrapper exited 0 on clean shutdown and left no orphan node process.

A temporary sleep inhibitor was attached to the managed service for the
long-running observation and follows the service lifecycle; it is not a
permanent host setting. The full-script IBD measurement remains in progress,
with no throughput or SwiftSync/Utreexo speed claim.

## Clean checkpoint capture and writer comparison

A later clean stop captured the v4 `state.dat` checkpoint at connected height
188,928, hash
`00000000000005400d9a675d37db5b2140887238fd1335db17cdb2159a1d6814`, with
971,817 headers. The file was 92,105,283 bytes and SHA-256
`be0de17b70d78f5ea68d5990656d1d11f23ac1cc591392c28c7db0e3e7c94159`. An
offline bounded comparison wrote the checkpoint through both the prior
buffered v4 encoder and the new 64 KiB streaming serializer. Both outputs were
byte-for-byte identical to the source and each other, with matching hashes.

Separate guarded 1,024 MiB-cap processes reported whole-process `VmHWM` of
273,520 KiB (about 267.11 MiB) for buffered reference and 182,796 KiB (about
178.51 MiB) for streaming; elapsed times were 1,540 ms and 1,547 ms. Both
include identical read/decode work. This was a single trial with different
cache state and clocks, so it supports no speed conclusion and does not prove
all node RSS is fixed. The decoded state and caller snapshot still occupy
memory. `VmHWM` is the process resident-set high-water mark; it does not
measure nonresident virtual allocations or cgroup file cache. The writer
comparison validates format-preserving checkpoint output,
not IBD completion or a change to consensus validation. See the
[streaming writer experiment](2026-10-17-state-writer-streaming.md) for native
gate results, exact command bounds, and durability caveats.

The installed CLI then passed a clean shutdown/restart proof at
2026-10-17T06:25:04.548465Z: it resumed at height 188,928 with the same
captured block hash. The same node process (PID 560505) later advanced to
190,895 with six connections. Its validation report had no AssumeValid
checkpoint and still required historical scripts. The attached GUI at
760×600 displayed live heights 189,659 and 190,819. Closing its node window
exited 0 while the same node PID continued syncing to 190,895. That GUI check
used a 512 MiB cap / 512 MiB reserve and peaked at 54 MiB over 112 seconds.
A modern-chain watcher for heights 600,000–600,127 was rearmed under a 256
MiB cap, but has no result because that height range has not been reached.
IBD remains incomplete.

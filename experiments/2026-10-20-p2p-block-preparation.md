# P2P block preparation pipeline — 2026-10-20

## Motivation and boundary

`PeerSession::poll` previously decoded each complete `block` payload on the
same manager thread that then called `PeerSync::on_block` and
`Chainstate::accept_block`. During direct-tip IBD, disk-body prefetch cannot
overlap that path because the delivered block is already in memory.

The session now yields checksum/authentication-verified raw block frames. Two
persistent workers decode the exact block serialization and run the full
context-free `CheckBlock`. A private-field `PreparedBlock` carries the
immutable body and exact parameter snapshot into the existing manager-owned
acceptance path. The consumer rechecks if parameters differ, then runs all
header-context, contextual block, UTXO, script, reorg, persistence, and
publication logic in its existing serialized chainstate order. Invalid
context-free blocks go through the regular rejection path; malformed payloads
remain attributed to their source session.

## Bounds and fallback

The pool has two workers, a maximum of four outstanding jobs, a 16 MiB
aggregate serialized-payload limit, and a 256 MiB conservative decoded-memory
reservation. Each body reserves 64 times its wire length before it is queued;
the reservation remains held through result consumption, including completed
results waiting for the manager. Peer ID plus session ID prevents stale
completion delivery after a disconnect/reconnect. Pool saturation or an
oversized reservation falls back to the original synchronous decode and
acceptance path. Fallback raw frames are bounded by configured peer count and
the protocol's 4,000,000-byte maximum frame size; each session reads at most
1 MiB per manager tick. Dropping `PeerManager` closes the queue and joins both
workers.

The default daemon path enables the pool. Set `AVILA_P2P_BLOCK_PREPARE=0` to
disable it for a matched synchronous baseline; tests can also select either
mode with `PeerManager::new_with_block_preparation`.

## Verification plan and evidence

The authored tests cover worker decoding and successful context-free checks,
trailing bytes, invalid proof of work, merkle mismatch, overweight blocks,
bounded outstanding jobs and reservation release, parameter-snapshot
rechecking, and a real loopback TCP block delivery through the manager.

No tests or builds have been run in this worktree. The P2P and consensus
validation is serialized centrally because the shared target build is in use.
There are no throughput measurements yet and no speedup is claimed. Compare
the same loopback/regtest block sequence once with preparation enabled and
once with `AVILA_P2P_BLOCK_PREPARE=0`, waiting for the connected tip in both
runs; this proves the functional path, not mainnet-scale performance.

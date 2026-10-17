# Bounded peer ingress — 2026-10-17

## Changes

`PeerSession::poll` now reads at most 1 MiB of socket bytes per call, shared by
the v1 frame decoder and v2 packet channel. Reads remain in 8 KiB chunks. The
session dispatches all complete frames already fed to its transport decoder
before returning; partial wire data stays buffered for the next poll. This
gives each peer a finite socket-read slice per sync tick while preserving frame
order and handshake processing.

The 1 MiB figure is a limit on newly read socket bytes, **not** a strict cap on
decoded event memory. A partial frame accumulated over earlier polls can be
completed in the current call; one payload may be as large as the existing
4,000,000-byte message limit. Decoding also allocates structured transactions
and vectors, so wire size does not directly bound heap use.

`PeerSync` now retains at most 50,000 distinct pending block-INV hints per
peer, equal to the protocol's maximum number of inventory entries in one
message. Duplicate hints are deduplicated; already-requested hashes do not
enter the pending set. When full, additional hints are dropped as a scheduling
choice. This queue is not a source of consensus validity: known active-chain
bodies are also scheduled from the headers-first fetch index, and a dropped
announcement may be repeated by its peer.

## Regression coverage and evidence

Added loopback TCP coverage for a fragmented v1 version frame followed by
35,000 ordered Pong frames, and a negotiated v2 session receiving two large
ordered inventory packets. Both assert that each poll reads no more than 1 MiB
and that later polls preserve message order and deliver the full stream. Added
a `PeerSync` regression that fills beyond the 50,000-hint cap, includes
duplicates, checks queue/set consistency, and verifies FIFO draining after
in-flight slots are freed.

The guarded native gate passed 1,152 Rust tests with five ignored, 14 Python
tests, and workspace Clippy. It ran under a 2,560 MiB cap with a 1,024 MiB
reserve, peaked at 1,680 MiB, and took 239 seconds. A rustdoc failure caused
solely by linking the private poll-budget constant was corrected by changing
that doc link to plain code formatting; the implementation remained unchanged.
Subsequent documentation, build, and smoke checks passed in 91 seconds at
1,090 MiB peak. Formatting and `git diff --check` also passed.

The deployed CLI SHA-256 prefix `fd20c6eb...` completed a real-peer check with
four connections. A clean restart proof covered saved height 155,785 through
resume at 155,788, and sync later continued to 156,067. Its validation report
still showed `assume_valid_checkpoint: null` and
`historical_scripts_required: true`; full IBD remains incomplete. These checks
do not establish a completed end-to-end IBD or quantify throughput. The two
queue/read bounds are scheduling and ingress controls, not consensus rules.

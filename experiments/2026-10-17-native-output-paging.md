# Native block transaction output paging

This check exercises the attached GUI's output-page navigation against a real
retained mainnet block. It complements the earlier native check of five pages
for a 440-input transaction; it does not qualify all viewport sizes or all
output counts.

## Candidate and bounded search

A local cookie-authenticated loopback RPC finder located block 275,318
(`00000000000000028f7229a62048c5401bc1f9e939ff144c15abdf38c0c31091`), with
1,339 transactions. Transaction index 291 was identified by txid
`42af068a6fede69b672226affacb35083a6f4c226e17d0798f8f8436db272cf4`; it has
one input and 111 outputs. The finder used four bounded `getblockinspect`
pages. It did not request or decode an unbounded full block. This identifies a
test candidate only; GUI behavior below was checked separately in the native
window.

## Native GUI result

The installed GUI binary for this proof had SHA-256
`2d36a706dfbb69fcf1e7975d76b4d91e510bbdb646464fdfff3d3b5b4d42af9c`; its
source fingerprint was
`2007ef695d70273d2aa9723e7d82871065a386b9c00a739a00e708888b1ce96c`. It was
built from `fc95eda` plus reviewed working-tree changes; the GUI test target had
86 passing tests.

At 1440×900 and 100% scale, the detail view showed outputs 1–100, advanced to
outputs 101–111, removed the Next control on the last page, and returned to
outputs 1–100 with Previous. The second-page capture included output index 100,
confirming that navigation reached the correct position. At 760×600 and 100%,
page 1 (outputs 1–100) was captured, but the attempt to confirm page 2 did not
complete; small-viewport output paging remains unverified.

The first detail request displayed OS error 11 / resource unavailable. An
explicit reselection returned the transaction details, including its 111
outputs. The fee remained unknown because the retained undo history did not
have complete legacy admission coverage. This does not establish automatic
retry behavior, delayed-network behavior, or a known-fee result for this
transaction.

Closing the GUI through Node → Close monitor exited with code 0 and left zero
GUI windows. The same daemon PID, 1,318,056, remained active and was still
reported at checked height 282,769 at 09:44:29.321384 UTC. This is continuity
evidence, not IBD completion.

The native GUI guard used a 512 MiB memory cap and 512 MiB reserve; peak memory
was 91 MiB over 454 seconds, with 8.21 seconds CPU. Separately, the bounded
candidate finder used four RPC pages under a 128 MiB cap / 128 MiB reserve,
peaking at 12 MiB over 2 seconds. That finder timing is not a GUI latency
measurement.

## Limits

This proves >100-output next/previous navigation only at 1440×900 and 100%
scale for this transaction. It does not verify page 2 at 760×600, other zoom
levels, nonzero-fee rendering, screen readers, cross-platform behavior, or
automatic retry after an RPC timeout. Full IBD remains in progress.

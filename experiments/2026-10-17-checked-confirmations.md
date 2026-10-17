# Checked-frontier confirmations and state-sensitive RPCs

## Observation

During mainnet sync, a query for block height 300,000 returned
`confirmations=671840`, while a validation report at the same observation had
`connected_height=301625` and `headers=971839`. The returned value matched the
best-header arithmetic (`971839 - 300000 + 1`) rather than the checked active
chain depth. This is a captured pre-fix RPC observation, not a claim that all
RPC methods or GUI displays had the same behavior.

Bitcoin Core v31.1 computes block depth against the active chain tip and
returns `-1` when a block is off that chain. Its raw-transaction RPC
distinguishes transactions queried with an explicit block hash from those
found through txindex. See the upstream
[`ComputeNextBlockAndDepth` and block JSON code](https://github.com/bitcoin/bitcoin/blob/v31.1/src/rpc/blockchain.cpp#L109-L169)
and [`getrawtransaction` result metadata](https://github.com/bitcoin/bitcoin/blob/v31.1/src/rpc/rawtransaction.cpp#L311-L319).

## Implementation and validation status

The current source introduces a checked confirmation frontier based on
active-chain membership and `checked_height()`, rather than the best-header tip
or an unvalidated speculative suffix. It returns `-1` for headers and blocks
outside that checked active prefix, reports `nextblockhash` only within the
checked prefix, and keeps detached raw transactions at zero confirmations.
Explicit-block `getrawtransaction` results use Core-shaped `in_active_chain`
metadata; txindex results do not gain that field merely because an index found
a block.

It also gates selected wallet/UTXO and transaction-admission queries on
pending script checks. Once a checked block prefix is available, it updates
the mempool from those validated blocks before the query reads chainstate or
mempool state. If a pending check fails after a valid prefix, that prefix is
published and the requested query closure is not run. Frequent status, report,
inspector, and receipt queries remain non-draining. This changes query
sequencing only; it does not relax or skip consensus validation.

Validation attempt 1 passed the consensus suite (628 passed, four ignored) and
17 Python tests, then stopped at RPC-test compilation errors caused by three
`hex::encode` calls needing borrowed inputs. Attempt 2 compiled and passed 71
RPC tests but failed two fixtures: appended transactions had stale witness
commitments, and the 99/100-maturity wallet scenario consumed its only mature
coin before a later funded-PSBT assertion. The fixtures were corrected. Attempt
3 passed 628 consensus tests (four ignored), 73 RPC tests, and 17 Python tests;
Clippy then found two `expect_used` warnings in new tests. Those calls were
replaced with diagnostic `unwrap_or_else` handling, without a lint suppression.

Attempt 4 passed the final gate at source fingerprint SHA-256
`bc147fa2637e476f6f6bf1481e8184dc1b4bb768d005cf0504cef3eb1ba076d4`: 628
debug consensus tests (four ignored), 73 debug RPC tests, 1,194 release tests
(five ignored), and 17 Python tests. Formatting, workspace all-target Clippy
with GUI/devtools and warnings denied, rustdoc with warnings denied, paired
CLI/GUI release builds, and config/inspect/GUI-help smoke checks passed. The
build ran under a 2,560 MiB cap with a 1,024 MiB reserve; peak was 2,308 MiB
over 349 seconds. Installed paired binaries had SHA-256 `c9cad90e2d6c3ab80c2b936fc65e4a0b77ef81fa950baf318bef9abf0e9d46ac` (CLI) and
`5a1416908fcedb5676b0d9bcd062c6d8c16de3727ace0c366227d94e865bad4e` (GUI).
The install guard used a 256 MiB cap/reserve and peaked at 122 MiB over 3
seconds.

The cleanly captured v4 checkpoint used for the restart proof was at height
309,143, hash
`000000000000000032ec2752cca620874e5ca87f96c290e9c17853babfab8b8d`, 101,243,835
bytes, file SHA-256
`de12c168a046bd7b8a1be05b1b6b702cf7986be851b0f54d157327d7e635d0c8`. Its copied
bytes and checksum were reverified against the original before the final
candidate was tested. The installed CLI then automatically restarted as PID
1597809 (start ticks 3,848,734) with unchanged configuration, arena limit 2,
3,072 MiB service cap, swap disabled, no AssumeValid checkpoint, no snapshot,
and historical scripts required. At 2026-10-17T11:00:35.334576Z it resumed at
height 309,143 with the saved hash matching.

At 2026-10-17T11:00:56.296Z–11:00:56.453Z, the new CLI completed 15 RPC calls
in one bounded runtime attempt. `getblockheader`, `getblock` verbosity 1, and
explicit-block `getrawtransaction` for height 300,000 each reported 9,169
confirmations; checked height was 309,168 before and after the calls, while
best headers were at 971,843. A future header at height 310,168 reported
`confirmations=-1` and no `nextblockhash`; that selected future header was
inactive, not fully checked, and had no available body. The RPC sequence ran
under a 128 MiB
cap/reserve in one second; the sampled process peak missed the short run, so no
memory claim is made. This verifies the observed RPC behavior and checkpoint
continuity for this run, not full IBD or modern-range coverage. A
600,000–600,127 collection and health observation remains pending.

A fresh native attach-GUI smoke on the installed GUI binary at 1440×900 showed
connected height 309,302, headers 971,843, `full_validation`, historical
scripts required, and no snapshot. The block inspector loaded height 300,000
with the expected hash, active-chain and fully-checked flags, 237 transactions,
and block weight 515,240 WU; its first 100-of-237 transaction weight-map rows
were visible. Closing the monitor exited the GUI with code 0 and zero remaining
windows while daemon PID 1597809 (start ticks 3,848,734) continued from height
309,302 to 309,603. The guarded capture used 512 MiB cap/reserve, peaked at 107 MiB,
and took 55 seconds. This is attach/overview/block-map/close evidence only; it
does not requalify compact layouts, transaction paging, fee detail, or the
earlier wallet-focused GUI captures from a different binary. The capture
helper's extra post-close wait assertion failed because the window had already
closed; independent GUI process-exit, zero-window, and daemon-identity checks
confirmed successful close behavior.

The covered cases include header-only and pending-script confirmations,
explicit versus indexed raw-transaction metadata, 99/100 confirmation coinbase
boundaries despite a best-header successor, checked UTXO reads, a
confirmed-then-spent mempool output, and pending classic/witness proof rejection
before validation followed by acceptance after a checked query. The pending
script failure fixture also checks that a completed valid prefix removes a
confirmed transaction from the mempool without executing the failed query.
Full IBD completion, throughput, and modern-range coverage are not established
by these proofs.

Avila's existing coinbase maturity threshold remains 100 confirmations at the
checked tip, meaning spendability in the candidate next block. This is
distinct from Bitcoin Core wallet's conservative 101-confirmation display
policy ([Core v31.1 `GetTxBlocksToMaturity`](https://github.com/bitcoin/bitcoin/blob/v31.1/src/wallet/wallet.cpp#L3060-L3076));
no wallet maturity parity claim is made.

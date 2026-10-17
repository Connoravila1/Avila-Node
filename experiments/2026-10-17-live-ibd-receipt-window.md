# Bounded live IBD receipt-window measurement protocol

## Purpose and limits

`tools/measure_live_ibd.py` passively samples one bounded window of ordinary
mainnet validation receipts through a numeric loopback RPC endpoint. It never
starts or stops the node and changes no consensus or connection behavior. It refuses to run unless RPC reports IBD,
`assume_valid_checkpoint: null`, and `historical_scripts_required: true`; the
connected/checked height must reach the entire requested window. Every receipt
must say checks were enabled and its block hash must match the active chain.
The default is heights 600,000–600,127; `--count` is limited to 128.

This is a per-block operational measurement, not an IBD benchmark or proof of
SwiftSync/Utreexo performance. Receipt `wall_ns` describes the serial connect
pass and excludes deferred script-worker wait. `script_checks` can be queued
work, not completion, and `verified_hits` count verified-script-cache skips.
If the sampler's first checked-height observation is already at or above the
target start, it may still report per-block receipts, but its external elapsed
window is marked unavailable. Otherwise it retains the last status strictly
below the target start and ends at the first status at or above the target end.
This gives an enclosing interval even when fast IBD crosses the exact boundary
between polls. The report includes actual starting/ending heights, actual
advanced checked-block count, prefix/suffix blocks outside the requested
window, and the descriptive rate for that actual height delta. It labels exact
target-height endpoints when both happen to be observed. Elapsed time remains
bracketed by status RPC observations, not the exact instant each block
connected; the polling/RPC allowance applies to status-observation timing and
does not bound target-only duration when prefix or suffix blocks are included.
It does not infer whole-chain IBD time or a speedup.

The sampler takes one bounded 2,016-entry receipt-ring snapshot after the
checked tip reaches the window end; it does not make per-height receipt calls
or retry a partial/missed window. It aborts when a target receipt is missing
or duplicated, a target block hash differs from the active chain, checked
height moves backward, uptime decreases, or the active hash at a previously
observed checked tip changes. It rereads target hashes after receipt
collection and checks the window endpoint again. A reorg during the operation
invalidates the sample rather than being silently combined.
The program writes no partial result. It publishes one new output file with a
same-directory atomic no-overwrite operation; it refuses overwrite or resume.

## Invocation

Choose a target height based on observed node progress; the default is useful
for a later transaction-heavy era, but may be changed for a future bounded
window. Set paths for the local executable, the daemon's exact config, and a
new output filename. For example:

```sh
AVILA_CLI=/path/to/avila-node
AVILA_CONFIG=/path/to/avila.toml
OUT_DIR=/path/to/existing/results-directory
tools/guard_run.sh --max 512 --reserve 2048 -- \
  python3 tools/measure_live_ibd.py \
    --cli "$AVILA_CLI" --config "$AVILA_CONFIG" \
    --output "$OUT_DIR/ibd-receipts-600000.json" \
    --start-height 600000 --count 128 --wait-seconds 86400
```

Select the cap/reserve from current `MemAvailable` according to `AGENTS.md`;
the example values are not a host-independent recommendation. The output
directory must already exist. The process waits for RPC readiness and the
checked window without managing the daemon. It can wait at most seven days;
per-call timeout is at most 60 seconds. Receipt and CLI output are bounded,
and the final JSON is capped at 2 MiB.

An optional `--node-pid PID` adds `/proc` CPU, endpoint RSS, and process I/O
counters. Use it only for the daemon process. The sampler verifies that its
executable matches the selected CLI binary and that the daemon command line
uses the selected config, then rechecks PID start time and executable identity
throughout. These are process-accounted bytes and endpoint RSS readings, not
device I/O or peak memory. No process counters are emitted without this check.
The CLI binary, config, and sampler source SHA-256 digests are included; config
contents and RPC error text are not written to the result.

Without `--node-pid`, monotonic RPC uptime is used to reject observed uptime
decreases, but a short restart that occurs entirely between polls cannot be
proved absent. For a supervised live measurement, provide the daemon PID so
process start time and executable identity are checked as well.

## Interpretation

Retain the output JSON with the node revision, host/resource profile, and
guard-run cap reported separately in the experiment log. Per-block receipt
rows preserve the measured counters and serial wall times; summary totals and
median/p95 are descriptive for only that window. `external_sample.available`
must be true before quoting its sampled enclosing interval, and the actual
height delta, prefix/suffix counts, and status-observation allowance must
accompany it. The allowance is not a target-only duration bound if the
enclosing interval includes extra blocks. Compare runs only when validation
policy, binary/config provenance, cache settings,
hardware/load, and window are stated. This tool does not compare against an
alternative sync implementation, measure complete IBD, or prove UTXO
membership, script validity beyond the node's recorded checks, or any
SwiftSync/Utreexo security property.

## Early native trial — 2026-10-17

A successful 128-receipt trial covered heights 116,138–116,265. The retained
receipt rows total 1,103 transactions, 1,920 spent coins, 2,192 created coins,
975 recorded `script_checks`, and zero `verified_hits`. The serial connect
`wall_ns` median was 416,549.5 ns, p95 1,942,264 ns, and maximum 59,446,367 ns.
These are receipt counters for this window; `script_checks` is not asserted to
mean one completed check per input.

The external sample enclosed checked heights 116,123–116,277: 154 actual
advanced blocks, including 14 prefix and 12 suffix blocks outside the target
window. The sampled status interval was 1.9099144 seconds. Its conservative
status-observation allowance was 50.5 seconds, so the sample does not support
a precise performance claim. The 1.9099144 seconds is not a measurement of
the 128 target blocks alone and is not an IBD speedup. This early-chain trial
also says nothing about witness-era or other modern-chain coverage.

The sampler ran under a 256 MiB cap, peaked at 16 MiB, and completed in 19
seconds. The first trial failed because the CLI emits `getblockhash` as raw,
unquoted hex rather than JSON; strict raw-hash parsing was added. A subsequent
trial exposed that the external baseline retained the first pre-window status
rather than the latest one; the baseline now advances with each below-window
observation. Fourteen Python tests pass, including the bounded subprocess
transport and the baseline-selection sequence. After the updated CLI was
deployed, a separate 600,000–600,127 watcher was armed with the node PID pinned.
The node is still far from that window and full IBD remains incomplete; no
artifact or result exists yet.

The revised sampler was also exercised on a separate 16-block native probe at
heights 233,609–233,624. The sample was accepted with full-validation policy
(`assume_valid_checkpoint: null`, historical scripts required), and all receipt
hashes were checked against the active chain during collection and rechecked
afterward. It recorded 5,246 transactions, 11,420 spent coins, 16,111 created
coins, 5,230 script-check jobs (for non-coinbase transactions), and 64,520
sigops. The first status observation
was already above the target start, so external timing was unavailable; this
probe is not a speed result. Its artifact is `ibd-receipts-retry-native-233609.json`.
The separate 600,000–600,127 collection remains pending.

## Continuity retry follow-up — 2026-10-17

The separate modern-chain collector attempt terminated at 07:36:18 UTC after
373 seconds with exit 1 when its prior-tip continuity `getblockhash` call
failed transiently. The sampler retries transient `RpcCallError` failures for
both status reads and the pre-window continuity check, preserving the last
successful observation until a complete observation succeeds. Height rollback,
same-height hash changes, uptime decreases, active-hash mismatches, and policy
or identity failures remain fail-closed; the cheap height/hash/uptime checks
run before the retryable continuity call. Final receipt collection and its
rechecks are not retried.

All 17 sampler unit tests passed under a 256 MiB guard cap / 256 MiB reserve.
They include transient continuity-hash recovery through a valid receipt
window, wrong-hash rejection, and a restart/uptime rollback that fails before
calling the busy hash RPC. The short test process peak was missed by the guard
sampler, so no memory figure is claimed. The sampler source SHA-256 was
`cd3a8f6449dda57ce1476b6d41bb3d21a9a87ee1c4b5c2e958e71ec6d5b22a81`; the test
source SHA-256 was
`c51044781a7d32228525e67288a298994c2ccb71a4c18ea35a41ea0444a636bc`.
No Rust build or node behavior changed. The 600,000–600,127 result remains
pending. Attempt 2 was armed at 07:41:29.770 UTC as
`avila-ibd-receipts-600000-p838059-a2.service` (collector PID 903060), against
the same node PID 838059 and helper SHA-256 above. It uses a 256 MiB cap and
256 MiB reserve, 15-second RPC timeout, and 1-second poll interval. Its output
is separate from the terminal first attempt. After the clean arena-2 restart,
the modern-window collector and health watcher were rearmed against new node
PID 943399. The 600,000–600,127 target receipt has not yet arrived.

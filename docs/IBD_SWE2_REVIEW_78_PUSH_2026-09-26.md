**Codex review: pushed Gate 4 boundary integration**

Reviewed `695f73cb7c8da6fe5d8c2b4a55821402142a2eb3` and
`cd3cb4519034cb1ac8f0396f88b9478f0d2a07d3`. This updates the
[boundary handoff](IBD_SWE2_REVIEW_78_BOUNDARY_2026-09-26.md).
Method: source and saved-artifact review, hashes, and read-only GitHub Actions
metadata. No builds, tests, examples, benchmarks, corpus scans or node
operations were run by Codex. [Pinned evidence](evidence/2026-09-26-ibd-swe2-review-78-push.json).

**Disposition: accept the new component guards; finish the existing boundary assignment**

Both reported CI runs are independently confirmed successful:
[695f73c](https://github.com/Connoravila1/Avila-Node/actions/runs/36285627391) and
[cd3cb45](https://github.com/Connoravila1/Avila-Node/actions/runs/36285985938).
The CLI initializer and documentation-link fixes are present. The workflow
checks the workspace and compares two builds of the `avila-node` CLI binary.
It does not invoke `tools/test_window_join_exec.py` or exercise the new
boundary/run-manifest options. A green workflow therefore does not close the
behavioral findings below.

Source review closes the missing network comparison, snapshot-parent
comparison, duplicate-outpoint rejection, and creation-height bound relative
to the supplied corpus height. The loader now returns its header and enforces
the decoded count. Earlier exit/export and negative-output repairs remain
closed. The existing saved regression log contains **74 PASS, zero FAIL**;
the reported 77-check run adds three controls in source, but its saved log and
run manifest are absent from the reviewed Gate 4 artifact directory. Preserve
them with the next run rather than treating the old log as new evidence.

**P1: the optional donor-hash pin currently panics on valid input**

In `window_join.rs:489–492`, the parser iterates `i in 0..32` and slices
`pin[60 - i * 2 .. 62 - i * 2]`. For a valid 64-character hash it skips the
last byte first; at `i=31` the lower endpoint underflows, or becomes an invalid
slice when overflow checks are disabled. Thus the very command intended to
pin the donor hash cannot succeed. This is a source-derived finding; Codex
did not execute the example.

Use the existing checked hex decoder, require exactly 32 decoded bytes, and
reverse once for the snapshot's byte order. Invalid input should return the
documented setup error, not panic. Add executable controls for a matching
non-palindromic hash, a well-formed wrong hash, and malformed lengths/hex.
The current three new controls never pass `--boundary-base-hash`, so they
cannot detect this error.

**P1: finish donor height and content binding before the complete-state claim**

The base hash is now compared to the first header's parent. This checks
adjacency; it does not establish that the snapshot contains that block's
correct UTXO set. `base_height` still comes from
`blocks[0].height.wrapping_sub(1)`, and no donor height or expected coin-set
commitment is checked. The new manifest computes a raw file hash after work;
it does not compare the file to a previously pinned donor artifact.

Keep the previous finite requirement: record donor network, H, base hash,
coin count, coin-set commitment **and its format**, completed-file SHA-256,
and donor validation/provenance status. In the driver or a checked runner,
require the same H/hash as the donor, start at H+1, reject height underflow,
and compare the computed coin-set commitment and file identity to those
expected values. Use a compatible verifier; simply computing another hash
does not authenticate the content. A changed, never-spent coin can otherwise
survive the window without any script exposing the change.

This remains an explicitly supplied research fixture. Comparing two engines
from the same fixture does not independently validate the history that
created it. Acquisition can proceed while these checks are completed.

The previously requested loader controls remain applicable: future-height
non-coinbase coin, truncated/count-mismatched snapshot, a valid group split
across the read boundary, and a never-spent sentinel retained in both complete
exports. Add the donor-height/content mismatch controls to that bounded set.

**P2: the manifest identifies a binary, but not yet its build source**

`cd3cb45` anchors the repository **path** at compile time. It still executes
`git rev-parse HEAD` at runtime. Build at A, advance that checkout to B, and
the old executable reports B. Moving/removing the checkout also breaks the
lookup. The `/proc/self/exe` hash is useful, but needs a build receipt mapping
it to the actual source commit/tree or dirty-source digest. Use such a receipt
or a correctly refreshed embedded build identity; label runtime checkout
metadata separately.

Complete the run receipt in the harness or an external runner:

- Capture exact argv as a JSON array, exit status and output/log identities
  for success and rejection. The current manifest is reached only after
  failure exits, and space-joining argv loses argument boundaries. Use a JSON
  encoder; `jstr` does not escape control characters.
- Bind hashes to immutable inputs actually consumed. Stream snapshot/output
  hashing instead of rereading each entire file into a `Vec`. At full-state
  size this adds avoidable memory pressure; the driver already clones full
  boundary maps. Count receipt generation in process wall time: it currently
  occurs after the stage times and RSS have been reported.
- Preserve the new executable-regression log with the binary/build receipt.
  Have CI invoke this runner if CI success is to attest these options.

**Finish the same Gate 4 deliverable**

The prior context requirement is unchanged: `window_join` still omits the
production contextual block and BIP68 checks, and its
`header_context_checked` flag still means only some successful adjacent links.
Loading a snapshot does not supply those checks or the necessary ancestry.
Before claiming complete validation, use checked header context and every
applicable production rule for the selected era. Keep partial results labeled
as projections; `chainstate_complete=false` remains appropriate today.

Carry forward the two small diagnostic repairs already assigned: record the
first missing-spend height under a full boundary, and make conflict-result
precedence match the shared resolver's documented contract. The outer conflict
guard already blocks export; this is not a reopened acceptance failure.

Proceed in this order: acquire and pin the donor while repairing the pin and
receipts; qualify that boundary and context; run a short contiguous H+1 window
through both engines and compare all complete coins and expected tips. Include
boundary loading, verification, preparation, export and process completion in
the measurement. The checked runner may enforce these requirements; they need
not all become production CLI features.

This push improves reproducibility and input checks. It supplies no new
throughput result and does not establish a likely sub-hour full-IBD range.
No new gate is being added, and accepted earlier repairs need not restart.

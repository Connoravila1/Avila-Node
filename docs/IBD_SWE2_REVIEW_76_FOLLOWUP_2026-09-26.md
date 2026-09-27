**Codex audit: experiment 76 follow-up repairs**

Date: 2026-09-26. This updates the disposition in the
[previous review](IBD_SWE2_REVIEW_76_2026-09-26.md); its Gate 3 acceptance
requirements remain in force. The
[one-hour first-launch objective](IBD_PRODUCT_OBJECTIVE.md) is unchanged.

Review method: inspect source, regression definitions, archived census JSON,
replay JSONL, and the corpus manifest; recompute arithmetic from those records.
No tests, benchmarks, corpus scans, live-node operations, or cleanup were run
by Codex. [Evidence](evidence/2026-09-26-ibd-swe2-review-76-followup.json)
records source hashes, saved outputs, arithmetic, and evidence limitations.

**Current disposition after the v5 handoff: move to Gate 3**

The bounded census/replay baseline is adequate to proceed with the state
experiment. The new [v5 evidence record](evidence/2026-09-26-ibd-swe2-review-76-v5.json)
pins this source/artifact review; Codex did not execute the experiments or tests.
The earlier disposition below is retained as history and is superseded by this
update where the new artifacts address it.

- [`matched-calib.json`](../experiments/results/gate76-followup/matched-calib.json)
  now preserves the Python comparison. Both selection digests match the v5
  replay, as do 223,295 transactions and 517,819 inputs. The structural count
  is 524,092 and the helper-attempt count is 526,534, a ratio of 0.995362123.
- [`replay-v5.jsonl`](../experiments/results/gate76-followup/replay-v5.jsonl)
  records 526,534 shape-matching attempts, zero nonmatching attempts, 526,528
  backend calls, and no script-failing transactions. The new shape counters
  reconcile with the helper count on this legacy sample.
- [`regression-exit-log.txt`](../experiments/results/gate76-followup/regression-exit-log.txt)
  records the resolver checks, immature replay exit 1, and a passing zero-worker
  rejection check. The zero-worker line does not preserve its exact exit code;
  the test still checks any nonzero status. The broader harness-hardening
  advice below remains appropriate for Gate 3's acceptance suite.
- [`blk05625-v3.json`](../experiments/results/census-2026-09-26/blk05625-v3.json)
  has the same input metadata as v2, still verifies 83/83 transaction Merkle
  roots, and changes shared compression work by exactly 105 calls to 2,382,147.
  The source now includes the in-range SINGLE-output hash. It charges each
  matching witness DER-shaped item at that input index; this remains a
  structural model rather than an executed hash counter.
- SWE-2 reports a clean `cargo test --release -p avila-consensus` rerun:
  551 library, 9 fault-injection, and 19 property tests. The supplied artifact
  directory does not include the complete Cargo output/exit record, so this
  is a reported pass, not independently verified by this audit. Attach the
  existing log if available; preserve full test logs with the Gate 3 handoff.

**Retain one interpretation qualification; no additional replay is required
to start Gate 3.** The classifier is the census's outer-shape predicate, not
strict DER validation. It does not check the R/S tags, integer lengths, signs,
or redundant padding that `interpreter::is_valid_signature_encoding` checks.
Thus zero nonmatching attempts excludes misses by this shape predicate among
the observed helper attempts; it does not prove every signature was strict
DER or exclude all uses of lax encoding.

Nor do these aggregate counters establish exactly 2,442 CHECKMULTISIG retries.
They do not identify distinct executed item occurrences, unused pushed items,
or attempts by opcode. Repeated signature/key attempts are a plausible
explanation supported by the interpreter's behavior, but attributing the
entire net difference requires that additional reconciliation. In general,
`attempts >= structural items` is not an invariant: pushed items can remain
unused or be discarded. Keep the result worded as:

> The matched structural count is 0.464% below executed helper attempts.
> Every observed attempt matches the census shape predicate. The excess is
> consistent with repeated signature checks, including multisig retries;
> exact attribution of the net difference has not been recorded.

Use that wording in the researcher report and LOG instead of "cause assigned"
or "lax-parse eliminated entirely." The current close agreement is useful
within this sample. It does not establish a universal correction factor,
whole-history workload, or new performance gain.

Gate 3 is the priority now. Keep the pinned initial state, contiguous selected
chain, complete consensus predicates, canonical complete-coin comparison,
independent Bitcoin reference checks, and rejection suite from the existing
work order. Establish exact correctness before interpreting state-path speed.

**Earlier disposition before v5: evidence closeout alongside Gate 3**

The three primary implementation repairs are present. The witness offset now
uses transaction-relative coordinates; maturity invalidity reaches a nonzero
exit; the calibration tool selects transactions rather than scaling a whole
window's density. These address the mechanisms identified in the last audit.

The handoff's stronger claims of fully verified closure and an explained
calibration residual still need the bounded follow-ups below. None requires
postponing the independent Gate 3 state experiment or expanding the source
index to resolve the entire history.

| Item | Reviewed evidence | Disposition |
| --- | --- | --- |
| Witness offset | Corrected slice and length assertion; archived 83-block result with 83 verified transaction Merkle roots | Accept this defect's repair on the supplied witness-containing sample |
| Invalid maturity and zero workers | Correct exit paths, source-vector assertion, accounting, and binary-level regression definitions | Implementation repaired; preserve actual regression execution and exit records |
| Matched-subset selection | Rust and Python construct ordered block-hash/transaction-position membership digests; archived Rust digest and counters exist | Matching mechanism implemented; archive the Python comparison output to complete reproducible evidence |
| Verification-helper versus backend counts | Archived v4 run reports 526,534 helper attempts and 526,528 backend entries | Accept the six-attempt difference at these counter boundaries |
| Attribution of the 2,442-attempt structural residual to lax DER | No per-attempt classification or category reconciliation in the reviewed records | Explanation remains unestablished; correct the claim or supply the breakdown |
| Consensus test suite | Handoff reports 32 filesystem failures; no clean release-suite result supplied | Rerun the required release suite and preserve the result |

**What the archived results establish**

[`blk05625-v2-fixed.json`](../experiments/results/census-2026-09-26/blk05625-v2-fixed.json)
records 83 blocks, 340,380 transactions, 634,469 non-coinbase inputs, and 83
verified transaction Merkle roots. The source now reconstructs stripped
transactions using `wit_start_rel` and checks the reconstructed length. A
Merkle mismatch makes the command exit nonzero. This exercises the previously
broken branch on a witness-containing corpus. It does not establish witness
commitment verification, selected-chain validity, or every census cost model.

[`replay-v4.jsonl`](../experiments/results/replay-v4.jsonl) records:

| Quantity | Value |
| --- | ---: |
| Total non-coinbase inputs | 671,771 |
| Executed transactions | 223,295 |
| Executed inputs | 517,819 (77.083%) |
| ECDSA helper attempts | 526,534 |
| ECDSA backend calls | 526,528 |
| Script-failing transactions | 0 |
| One-worker script-stage elapsed time | 59.508 seconds |
| Final process RSS high-water mark | 460,808,192 bytes |

Its executed-set digest is
`2276ffea366df4f181a9379f46fc2fb470239129b4b3a252bd6f49ca7748abb5`.
Both recorded input-accounting identities hold. The post-worker RSS record
also fixes the previous preparation-only measurement. This shared-host run
does not establish a performance improvement or full-IBD capacity.

**Closeout 1: preserve the matched calibration and qualify its residual**

The reported structural count of 524,092 gives:

```
526,534 - 524,092 = 2,442 attempts
524,092 / 526,534 = 0.995362123
relative difference = -0.4637877%
```

That is useful agreement on the reported matched sample. However,
[`der_shaped`](../tools/ibd_census.py) checks item length, the sequence prefix,
and an outer-length byte; it is not a strict DER validator. The current
instrumentation does not count which executed signatures fail that shape
filter. In addition, the
[`CHECKMULTISIG` loop](../crates/avila-consensus/src/interpreter.rs) can try
one signature against several keys. Counting signature-shaped stack items
and counting verification attempts are different operations even when every
item is ordinary DER.

The six early returns establish a separate fact: six helper attempts did not
reach `secp().verify_ecdsa`. They neither explain nor rule out laxly encoded
signatures among the remaining backend calls. Aggregate counts cannot assign
the 2,442-attempt residual to a single cause.

For now, use: **"Reported matched-subset structural count is 0.464% below
executed helper attempts; attribution of the residual is pending."** Archive
the complete JSON stdout from `ibd_matched_calib.py`, its command and exit
status, corpus manifest identity, replay identity, and source/build identities.
The Python output was not found alongside the archived results in this review;
the structural count and matching Python digest currently survive in prose.
If retaining the stronger causal claim, supply per-input/attempt evidence
separating shape misses, repeated signature/key attempts, and unexecuted items.
That classification can wait while Gate 3 proceeds.

Before using the matcher for witness-era results, make it fail on differing
transaction/input totals, source-vector lengths, or an unsuccessful replay,
and validate the selected run rather than unconditionally taking the first
`run` record. Its current `ecdsa_ratio` includes only scriptSig DER items and
omits `witness_der_attempts`; combine the appropriate categories for witness
ECDSA. Bind the corpus bytes and execution context as well as the membership
digest. Matching positions alone does not bind supplied transaction bytes,
prevout metadata, or flags.

**Closeout 2: preserve rejection evidence and rerun release tests**

[`test_ibd_corpus_window.py`](../tools/test_ibd_corpus_window.py) now defines
the requested mature-plus-immature and missing-plus-immature transactions and
invokes the release replay binary. The driver prioritizes detected immaturity,
accounts for all four excluded inputs, and exits 1; worker count zero exits 2.
The builder now exits nonzero on source-txid mismatch as requested.

For the acceptance run, require the binary to exist: the script currently
prints `SKIP` and succeeds when it is absent. Assert the intended exit codes
1 and 2, not any nonzero result. Preserve stdout/stderr and build identity so
a missing or stale binary, panic, or later failure cannot stand in for the
intended rejection. Include a complete valid control that actually executes
script checks. Keep the identity-mismatch and Merkle-mismatch negative cases
in the bounded rejection evidence as well.

The `/tmp` capacity report is stale. At review time `df` showed about 15 GiB
available; a later filesystem observation, preserved in the evidence file,
also showed ample available space. Codex removed nothing. Filesystem-related
failures are not a passing suite, and this review cannot establish their
exclusive cause from the handoff alone. SWE-2 should run:

```
cargo test --release -p avila-consensus
```

Preserve the command, revision/build context, full result and exit status.
If a failure remains, classify its actual error instead of attributing it
to the earlier capacity condition. Do not delete another agent's probe data.

**Census qualifications before making a whole-history hash estimate**

The OP_0 shape repair, raw sighash-byte preservation, coinbase zero-leaf
accounting, and movement of shared BIP143 costs outside the input loop are
present. Two remaining details matter to the cost model:

- The new shared-cost section at `ibd_census.py:416` handles the full
  prevouts, sequences, and outputs hashes but does not charge the
  single-output hash for an in-range BIP143 `SIGHASH_SINGLE`. The actual
  implementation computes it at `sigchecker.rs:362`. Retain the input index
  with each hashtype and model this cost under an explicit reuse policy.
  Also distinguish the census's need-based model from the current node's
  eager precomputation of the three BIP143 shared hashes. The preimage-length
  docstring still incorrectly describes fixed hash slots as elided; they
  remain in the preimage even when their contents are zero.
- The archived pre-SegWit `-v2` files are earlier repaired outputs, not
  evidence of reruns after every subsequent census edit. They still lack
  the newly reachable multisig-shape category; `blk00765-v2.json` also has
  the old model label. Preserve their historical identity and bind each
  future result to the actual producing source version. Do not imply one
  filename suffix establishes a common implementation for all results.

These do not reopen the fixed witness offset or invalidate the legacy
replay's executed counts. Keep these estimates structural until the relevant
hash operations and execution categories have been calibrated.

**Next assignment**

Proceed with the existing bounded Gate 3 work order: pinned complete starting
state and contiguous selected chain; complete state predicates; byte-identical
canonical complete-coin exports and matching final tip; valid and invalid
fixtures checked against an independent Bitcoin reference. Report the last
valid state on rejection. Then measure all state-build, I/O, memory, and
durability costs separately from script checking.

Complete the release-test/evidence closeout and correct the residual's causal
wording alongside that work. Mark superseded interpretations in the older
reports and LOG, including the still-present blanket claim that script success
authenticates an arbitrary supplied scriptPubKey. The source-identity and
state/provenance checks carry that responsibility.

Avila Core can package this bounded Gate 3 case through its existing checker
interface if the integration stays small. Preserve the same acceptance
requirements and raw artifacts whether or not that optional packaging is used.

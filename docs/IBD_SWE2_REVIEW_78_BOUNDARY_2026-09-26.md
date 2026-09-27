**Codex review: validation-contract closure and snapshot boundary integration**

Date: 2026-09-26. This updates the
[previous follow-up](IBD_SWE2_REVIEW_78_FOLLOWUP_2026-09-26.md).
Method: source review, saved test/regression logs, manifest arithmetic,
export byte comparisons, and file/binary hashes. Codex ran no examples,
tests, builds, benchmarks, corpus scans, or node operations.
[Evidence](evidence/2026-09-26-ibd-swe2-review-78-boundary.json) preserves the
reviewed artifacts and identities.

**Disposition: close the earlier exit/export and negative-output findings;
finish boundary qualification with the planned real-state comparison**

The source now uses one invalidity guard for export and exit in both modes.
Script tasks retain block height, and the earliest failure updates the
materialization cutoff. `check_block` supplies the missing transaction rules,
including negative-output rejection. The saved executable log contains
**74 PASS checks and zero FAIL checks**; the fresh release log records
**579 passed, zero failed, two ignored**. These support the stated component
repairs. The binary-provenance qualification below still applies.

I independently checked the saved manifests: 419 matching adjacent links
across the full gapped sample, and 300 across the 301-block segment. All 354
and 290 supplied MTP values respectively equal the medians recomputed from
their recorded ancestor times. Both v3 projection files match their recorded
hashes and are byte-identical to the preceding exports. The fixture driver
and shared join source hashes are unchanged from the last review.

The segment records 412,825 successful script inputs, an increase of 28,566.
Equal terminal projections are compatible with different amounts of checked
work, as the report now explains. They remain partial projections rather
than complete chainstate. Do not restart the already accepted repairs;
acquire the real boundary while completing the integration below.

**Qualify the new `--boundary` path before relying on it**

The new `for_each_coin` correctly describes itself as a loader rather than a
verifier. The driver currently treats loading as enough to set
`starting_state_complete=true`. That is not yet a checked boundary:

- The loader validates magic, version and serialized coin count, but ignores
  the snapshot's network and base block hash. The driver does not bind either
  to its selected network or the first block's parent. The regression helper
  even emits mainnet snapshot magic while invoking the binary with regtest
  parameters; the saved success case therefore does not test network binding.
- `group::<true>(..., u32::MAX, ...)` disables the decoder's useful check that
  coin creation heights do not exceed the snapshot height. A supplied height
  is needed: the file header contains a base hash, not its height.
- The callback uses `HashMap::insert` without checking for an existing entry.
  Duplicate outpoints can silently collapse or replace records while the
  serialized count still matches the header. The driver ignores the loader's
  returned streamed count and reports the resulting map length instead.
- No expected donor content commitment or immutable file identity is checked
  before the file becomes the authoritative starting state.

For the bounded comparison, pin a donor manifest containing network,
**H**, base block hash, exported coin count, donor coin-set hash with its hash
format, and the completed file's SHA-256. Check the snapshot header against
that manifest, require the window to begin at H+1, and require its first
parent to equal the pinned base hash. Verify the content commitment; a raw
file SHA-256 and a serialized coin-set hash are different checks. The existing
`read_header` and verifier can help, but a computed hash must actually be
compared with the expected value. This is an explicitly supplied research
fixture, not a requirement to add a production assumeutxo commitment.

Require coin heights at or below H, unique outpoints, and agreement between
declared, decoded and unique coin counts. Reject an inconsistent snapshot
before using its coins. Retain the full starting set, including never-spent
coins, in both reference and join outputs. Corpus-hint disagreement may fail
the research input as inconsistent; it must not be presented as proof that
the underlying Bitcoin block is consensus-invalid.

Add focused executable/loader controls for wrong network, wrong base/hash or
height, duplicate outpoints, a future-height non-coinbase coin, truncation or
count mismatch, and a valid snapshot that spans the loader's read boundary.
Include a never-spent sentinel coin in the positive control. These qualify
the new boundary feature; they do not require another broad performance run.

**Keep the remaining validation scope explicit**

`header_context_checked` is currently defined as
`linkage_broken == 0 && linkage_checked > 0`. That establishes some checked
adjacent links, not complete header context. Rename it to describe linkage;
retain false/unevaluated statuses for expected difficulty, header timestamp
rules, contextual block checks and applicable sequence locks until performed.

The real-data driver still does not call `contextual_check_block` or BIP68
validation. Selecting a new donor tip may put the next window in an era where
these are required. Supply checked ancestry and use the production rule
helpers with the actual activation context before calling the real-state
comparison full validation. Computing an MTP is not itself checking all rules
that consume it. Keep `chainstate_complete=false` until the full path qualifies.
For the current incomplete diagnostics, label exports as partially checked
projections; `projection:"valid_prefix"` implies more than is established.

Two small boundary-result details belong in that integration: a `Missing`
spend under a full supplied state currently causes failure but does not set
its position in `first_bad_h`; record the earliest such position. Also give
`BoundaryConflict` precedence in the shared resolver if that is the advertised
result contract. Currently a loaded live coin can return `Coin` despite a
conflict marker, although the outer conflict counter correctly blocks export.

**Preserve one identifiable run**

`source-rev.txt` records binary SHA-256 `e4ee66fa…`; the executable present
during this review hashes to `761b400b…`. This does not establish that tests
failed, but it prevents tying the current executable and saved log to one
immutable run. The Git revision alone also excludes these uncommitted example
and library changes. Preserve source/diff hashes, binary hash, input hashes,
command, exit status and outputs together for the boundary comparison.

The current saved segment stages sum to **13.538 s**, including 10.504 s of
scripts and 1.722 s of join work; the prose table describes another run.
Generate the table from the named saved JSON. Separately account for header
index/manifest preparation and full boundary loading in the complete-run
measurement. Current timings remain shared-host diagnostics.

One reconciliation correction: saved segment v2→v3 counters show **3,165 more
resolved source specs**, **3,165 more boundary coins**, **2,199 more admitted
transactions**, and **28,566 more verified inputs**. The report's “+2,199
segment inputs” mixes transactions with inputs.

**Next handoff**

Have the live-path owner schedule the existing `dumptxoutset latest` export
or obtain an isolated reference donor export. Pin its returned height/hash
and content metadata. SWE-2 can perform the boundary qualification and load
the necessary header ancestry while acquisition is arranged. Then run a
short contiguous H+1 onward window through the join and incremental engines
with every applicable check, comparing complete coins and expected tips.

Return that complete real-window result with its immutable run manifest and
preparation-inclusive timings. Snapshot trust remains a fixture assumption
for this bounded test; the final first-launch benchmark must validate the
history producing it. This advances the existing Gate 4 assignment and does
not change the one-hour objective or establish a physical time floor.

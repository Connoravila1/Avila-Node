**Codex review: donor-pin repairs at dd69355**

Reviewed `dd69355bfb1889102fc9f0aa67330a0c1deed20e`. This updates the
[push audit](IBD_SWE2_REVIEW_78_PUSH_2026-09-26.md).
[Evidence](evidence/2026-09-26-ibd-swe2-review-78-donor.json) preserves source
hashes, the regression log, and relevant Cargo cache metadata. Codex reviewed
source and saved artifacts; no builds, tests, examples, benchmarks, corpus
scans or node operations were run.

**Accepted repairs**

The archived `exec-regression-2026-09-26b.log` contains **84 PASS and zero
FAIL** checks. Its non-palindromic hash case and wrong/short/non-hex cases
exercise the repaired option. Checked hex decoding, exact length and one
byte-order reversal close the previous hash-pin panic finding.

The optional donor-height and coin-set pins are implemented. The loader hashes
each decoded coin's `TxOutSer` and the driver compares the resulting commitment
with the supplied expected value. The representation agrees by source review
with Avila's verifier/coinstats paths and
[Core v29.0's coin serialization](https://raw.githubusercontent.com/bitcoin/bitcoin/v29.0/src/kernel/coinstats.cpp).
The saved positive fixture computes its expected digest in Python. This
accepts the implementation at that scope; real donor equality remains the
next integration check.

Also accepted: JSON argv arrays and control-character escaping, bounded
streaming file hashes, terminal validation exit-code recording, and shared
`first_missing` accounting feeding the full-boundary failure position.

**P2: refresh or independently bind the build identity**

Embedding the value closes the old runtime-HEAD substitution problem, but
`build.rs:23` watches only the caller's `AVILA_GIT_REV` environment variable.
It watches no Git or source paths. Cargo's recorded fingerprint confirms that
sole dependency, with the variable unset. An incremental build after a source
change can therefore retain an old emitted revision. This follows
[Cargo's change-detection rules](https://doc.rust-lang.org/cargo/reference/build-scripts.html#change-detection);
Codex did not run a rebuild experiment.

Supply correctly refreshed build inputs or appropriate Git/source change
dependencies. A `+dirty` suffix also needs a source/diff digest if used to
identify uncommitted code. A focused regression should rebuild changed source
with the same target directory and unchanged `build.rs`, then distinguish
the rebuilt binary from a preserved older executable.

For the upcoming measurement, a clean isolated build with an external receipt
binding source commit, build command/toolchain and binary SHA-256 is sufficient.
Do not delay donor acquisition to design a general provenance framework.

**P2: height zero still reaches an earlier unchecked subtraction**

`window_join.rs:296` evaluates `b.height - 1` before the new `checked_sub`
at line 474. The MTP preparation at line 332 does the same. Release builds
enable overflow checks in `Cargo.toml:75`, so an h=0 input panics before the
intended setup exit 2. This is source-derived and absent from the 84 checks.

Reject a snapshot-before-genesis setup before coverage preparation, and use
checked parent-height handling wherever genesis can reach those loops. Add
one executable h=0 boundary control asserting exit 2 and no state export.
This does not prevent use of a correctly prepared positive-height donor.

**Conditions for the planned real-window run**

The three donor pins remain **optional** in the CLI. The complete comparison
must explicitly supply `--boundary-base-height`, `--boundary-base-hash` and
`--boundary-txoutset-hash` from the independently recorded donor export.
Loading `--boundary` alone still sets `starting_state_complete=true` without
checking those optional pins. Keep the donor manifest, coin count, hash format,
file identity and validation provenance attached to the run.

The manifest now covers terminal validation exits 0/1. Earlier setup errors
and panics still bypass it; use the external runner for those receipts. The
current success test checks field presence, then deletes its temporary
manifest. Preserve the actual next manifest and verify its hashes against
the archived inputs, binary and outputs.

The supplied 579-pass rerun is reported, but the available `...26c.log` is
byte-identical to the previous review's log. Archive the next required test
run with its build receipt; no additional broad rerun is requested solely
for this documentation distinction. The already assigned loader refill,
never-spent-coin and malformed-snapshot controls remain part of qualification.

Proceed with acquisition and the acknowledged production context work in
parallel with these two focused repairs. Use the qualified full boundary and
checked ancestry to compare a short contiguous H+1 window through both engines,
including complete coin exports and expected tips. Account for preparation,
boundary verification, export and receipt generation in process wall time.

The earlier accepted repairs remain closed. Gate 4 remains open for the real
complete-state comparison and capacity measurements; this commit adds no new
speed result or basis for a sub-hour forecast.

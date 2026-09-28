**Capacity audit at 3198d50: a serious implementation gap, with a conditional forecast**

**Subsequent user direction:** the user has clarified that sub-hour completion
was not realistic and that the present result is insufficient optimization.
The [optimization work order](IBD_OPTIMIZATION_WORK_ORDER_2026-09-27.md)
supersedes the next-assignment ordering below: proceed with implementation and
matched production comparisons; reconcile the forecast alongside them. The
audit's evidence qualifications remain applicable.

Reviewed `3198d50d59bde33881f435c3bc2bf5dc13817435` and
[the capacity report](IBD_CAPACITY_MEASUREMENTS_2026-09-27.md).
[CI succeeded](https://github.com/Connoravila1/Avila-Node/actions/runs/36348331368);
its executable step independently reports 115 passes, zero failures and the
clean committed revision. The empty-selection repair is accepted. No prior
consensus-repair gate is reopened here.

[Audit evidence](evidence/2026-09-27-ibd-capacity-review.json) preserves the
small receipts, source identities, reported era inputs and arithmetic. Codex
ran no experiments, builds, tests, node operations or large-file comparisons.
The review read source and small manifests/logs, including the era header
manifests, rather than block bodies or snapshots.

**The current implementation is far from the one-hour objective.** The
strongest saved measurement is the complete 454001–454301 window on clean
`9986ea5`: 1,303,682 inputs verified in **29.323 script seconds**, approximately
**44,459 inputs/s**. Its state digest is unchanged and completion flags pass.
Internal wall is 83.142 seconds, receipt-inclusive internal wall 96.874,
and outer guard wall 98 seconds. The capacity table's 31.8-second / 41k row
still describes the preceding run, not this clean rerun.

At 44,459/s, a billion comparable inputs would require **6.25 script-hours**.
That is normalized arithmetic, not a claim that every historical input has
this cost. The rate is about 8.3% above the preceding recorded run; changed
conditions do not isolate the cause. A many-fold improvement from clearing
the laptop has not appeared. The evidence substantially lowers confidence in
sub-hour completion through incremental improvements to this path.

The roughly 24-hour script estimate is arithmetically plausible under the
report's assumptions. Its four input counts sum to **3.74 billion**. Using
its rates and early versus late pre-SegWit rates gives approximately
**23.3–25.0 script-hours**. That calculation is a scenario. It does not turn
the counts into measurements, establish a narrow likely interval, or supply
a physical lower bound.

Three issues need resolution in the forecast and next experiment:

1. **Make the whole-history quantities traceable.** The new report gives
   40M/500M/1.2B/2.0B era inputs, 500 GB of blocks, and 140M final coins
   without a pinned tip or a derivation of those values. The older
   `workload.json` contains sample extrapolations, including roughly 1.99B
   Taproot-era inputs inferred from a narrow late-era slice. It explicitly
   lacks a SegWit estimate and does not establish these new totals. Provide
   a machine-readable worksheet with source, height/hash, units, provenance
   and assumption ranges for each quantity. Calculate sensitivity rather
   than presenting 28–30 hours as a measured end-to-end interval.

   The 500 GB / 25 MB/s = 5.56 hours calculation is correct conditionally.
   Fitting those bytes alone into an hour requires 138.9 MB/s of application
   payload, before helper bytes and startup/drain. Neither 500 GB nor a
   “typical” connection was established by this run. Keep acquisition under
   explicitly specified representation and measured goodput conditions, as
   the accepted product objective already requires.

2. **Treat era rates as admitted-subset measurements.** From the report's
   denominators, executed shares are 83.4%, 66.6%, 58.8%, 49.5%, 46.8% and
   73.1% for the six new slices. The builder/header manifests also contain
   gaps in every slice. Zero reported invalidity in those diagnostics does
   not certify excluded work or make the admitted mix representative of
   every historical spend. Preserve that useful timing evidence with its
   exact scope and uncertainty.

   I found builder/header manifests for the six slices, but no corresponding
   execution JSONL, run manifests or guard receipts in the reviewed result
   paths or matching top-level temporary filenames. Recover existing output
   from SWE-2's session rather than automatically repeating the runs. Save
   argv, build/binary identity, admitted/excluded counts, stage timings and
   CPU telemetry. The 454k receipt is present and independently reconciled.

   The report also identifies a pre-BIP34 data/builder gap; SegWit is not its
   only unmeasured interval. One late-Taproot-era slice cannot establish that
   witness verification has the same cost as legacy verification: era, script
   mix, admitted subset, signature attempts and CPU conditions all vary.
   Report the executed ECDSA/Schnorr backend split and script mix. “Taproot
   era” does not mean every input uses Schnorr.

3. **Keep proposed improvements separate from demonstrated gains.**
   The harness currently calls individual `verify_ecdsa` and `verify_schnorr`
   through `sigchecker.rs`. There is no measured 3–5× / 2–4× integrated batch
   result here, and 8→32 cores is another hardware scenario whose scaling
   has not been measured. Stage overlap also shares CPU and memory resources;
   it cannot receive an arbitrary independent multiplier.

   The report's own serial assumptions expose the problem: 24 script-hours
   plus six state-hours becomes **10.8 hours after a fivefold script gain**,
   or **14 hours after a threefold gain**, before other work. A 5–8 hour total
   needs additional state parallelism or overlap with an explicit resource
   budget. Conversely, a single-threaded state's wall time cannot simply be
   treated as eight-core CPU demand. Measure or bound both before composing
   stages. Loading/exporting state per driver invocation must not disappear
   when a bounded-memory implementation processes multiple windows.

   BIP340 distinguishes efficient Schnorr batching from batching standard
   ECDSA without additional witness data; it supplies no universal speedup
   factor for this laptop. [BIP340 motivation](https://bips.dev/340/).
   The repository's existing advice-plus-field-patch experiment is a concrete
   candidate: about 2.35× receiver throughput on a synthetic all-valid set.
   Its producer work was outside the receiver timer. Count local production
   when required, or remote helper bytes/decoding/checking when supplied.
   Preserve individual script verdicts and the fallback path.

There is also a measurement qualification for the dedicated run:
`cpu_s=n/a` is in its saved guard receipt. The later CPU-sampling repair does
not fill that value retrospectively. The `mhz` field actually prints
unconverted kHz from `scaling_cur_freq`, averaged across cores and the whole
run. Such readings are not script-stage cycle counts or proof of thermal
throttling. Linux documents that the attribute may report the last requested
frequency rather than the exact hardware frequency.
[Linux CPU frequency documentation](https://docs.kernel.org/admin-guide/pm/cpufreq.html).
Use the available measurements with those labels; attach existing CPU-time
and utilization monitors to the next performance experiment.

**Next SWE-2 deliverable: reconcile the model, then test one concrete crypto candidate.**

Recover the existing era receipts, publish the auditable conditional worksheet
and separate measured values from assumptions. This is analysis of completed
work, not another round of state-engine repairs. Keep a conditional range
where data is missing and show which assumptions change the conclusion most.

Then compare the strongest existing advice/field-kernel candidate against the
ordinary backend on matched real script work, in the offline harness on the
same laptop. Use an isolated frozen build and the mandatory guard, with one
heavy job at a time. Preserve identical verdicts, attempt counts and input
coverage. Report receiver CPU/wall, helper production or acquisition, parsing,
fallback work, and the resulting script-stage gain. Treat broader assembly,
SIMD or other accelerator work as unmeasured candidates until tested.

This establishes whether a substantial improvement survives integration and
what work remains after it. Do not multiply speculative kernel gains into
another optimistic full-node forecast. It is also unnecessary to repeat the
large state comparison solely to repair the forecast's prose.

The [one-hour product objective](IBD_PRODUCT_OBJECTIVE.md) remains unchanged.
It is now a **high-risk research target**, with substantial measured evidence
against the current implementation meeting it. “As fast as the machine
allows” would remove the useful acceptance criterion. A forecast describes
an implementation under specified assumptions; it does not establish the
best achievable algorithm or change the user's objective.

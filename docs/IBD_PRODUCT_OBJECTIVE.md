**Product objective: first launch to full Bitcoin validation within one hour**

Accepted by the user on 2026-09-26:

> Install, open, fully validate Bitcoin within an hour on ordinary laptop
> hardware, under specified connection conditions.

This is an engineering objective. It is not an achieved capability, a forecast,
or a claim about the physical minimum. Retain the objective while experiments
establish which implementation and connection conditions can satisfy it.

**Acceptance boundary**

Start the clock at first application launch with an empty datadir and no
preloaded historical corpus. Finish in less than 3,600 seconds with all
required history acquired, every applicable Bitcoin consensus check satisfied,
the exact usable chainstate durably saved, and the fully checked frontier at
the benchmark tip. Record normal handling of blocks arriving during the run.

Historical block downloads, dictionaries, indexes, hints, proofs/advice,
reconstruction, hashing, scripts, state materialization, final work drain, and
the completion checkpoint all belong inside the clock. Also report IBD-start
time for diagnosis. Ordinary installation/setup can be reported separately;
historical acquisition cannot be moved into an excluded setup interval.

An assumed snapshot with historical validation outstanding does not meet this
boundary. Optimizations must preserve every check. Helper data is checked,
never trusted, and the correct slow path remains available.

**Reference conditions**

The initial reference laptop is the user's Intel Core i3-N305 class machine:
eight CPU cores, 32 GB RAM, NVMe storage, with no required discrete GPU or
external validation cluster. Record sustained power/thermal conditions,
operating system, build, resource limits, and competing load. Results on lower
memory laptops or other hardware need separate measurements before extending
the claim to them.

Clarified by the user on 2026-09-27: the primary acceptance run assumes the
reference laptop is dedicated to IBD, with other user applications and
competing research/build workloads closed for the run. Normal operating-system
services remain; record their observed load, power mode, and sustained thermal
conditions. Shared-use measurements remain useful diagnostics, but do not
establish the dedicated machine's capacity or a physical lower bound. This
benchmark condition does not authorize closing applications or stopping
services during ongoing research. Retain the mandatory resource guard and
choose any memory budget from available headroom and measured requirements.

Specify the connection by measured sustained application goodput, link
topology, serving sources, and all transmitted helper bytes. CPU class alone
cannot determine first-launch time. At the provisional 768 decimal GB corpus,
raw transfer requires 1.707 Gbit/s of payload for one hour. At 940 Mbit/s, the
one-hour application-byte budget is 423 GB: approximately 45% lossless savings
would be needed before allowing for startup/final drain. These are budget
calculations, not measured compression or a fixed future chain size.

Pin the mainnet height/hash and corpus size for each result and report the
date. Acquisition and validation should overlap, but both must complete within
the same wall-clock budget. A kernel benchmark, acquisition-only run, or
extrapolated whole-chain estimate cannot establish acceptance. Broader product
claims require representative repeated end-to-end measurements.

**Execution and evidence**

SWE-2 executes experiments and implementation; Codex audits evidence and advises.
Use the [researcher work order](IBD_RESEARCHER_WORK_ORDER_2026-09-26.md) and
[networking work order](IBD_NETWORK_WORK_ORDER_2026-09-26.md). Record measured
results, extrapolations, and hypotheses separately in the experiment log.
Failure of a tested path to meet the deadline identifies its remaining gap;
it does not by itself establish a hardware impossibility theorem.

For the first research batch, see the
[audit of experiments 72–75](IBD_SWE2_REVIEW_72_75_2026-09-26.md).
The repair pass and state-comparison boundary are covered in
[the experiment 76 follow-up](IBD_SWE2_REVIEW_76_2026-09-26.md).

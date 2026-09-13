# Experiment: <question>

Status: proposed / running / complete / rejected

Roadmap gate/workstream: <G… / W…>

Scorecard rows: <IDs from docs/SCORECARD.md>

Operating profile: <storage, checks, services, hardware, resource and privacy budgets>

## Question and hypothesis

What changes, why might it help, and what observation would disprove the hypothesis?

## Baseline and candidate

Record source revisions, dependencies, toolchain, configuration and build commands.
State validation coverage, trust assumptions and behavior that must remain equivalent.
Explain baseline inclusion/exclusion, version selection, tuning budget and any shared
validation implementation. State proposed stretch targets and regression tolerances.

## Workload and method

Record dataset source, license, checksums, network/activation context, hardware, OS,
resource limits, repetitions, warm/cold cache conditions and reproduction commands.
Use bounded adversarial inputs as well as representative ordinary workloads.
Record warmup/run order, sample counts, uncertainty method and outlier policy. Separate
local replay from network sync and time to active state from full historical validation.

## Correctness evidence

Record expected outcomes, invalid cases, state comparisons, differential tests and
any unresolved discrepancies. Explain any skipped checks or altered guarantees.

## Results

Report latency distributions, throughput, peak memory, disk writes, bandwidth,
recovery behavior or other metrics relevant to the question. Include variability,
regressions and unsuccessful trials.
Account for local and required helper/proof/index costs, first-use preparation and
steady-state behavior. Link manifests, raw results and correctness checks.

## Interpretation and reuse

State what the evidence supports, its limits, follow-up work, and the smallest
implementation another project can reuse. Link the code and recorded results.

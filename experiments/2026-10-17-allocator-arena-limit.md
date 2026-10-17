# Allocator arena limit during managed mainnet IBD

**Status:** a baseline OOM is verified; the allocator-limit hypothesis test is
ongoing. No cause, memory win, speed result, or completed-IBD conclusion has
been established.

The installed full-validation CLI (`adfa4d2c…`, process 760476) was killed at
2026-10-17 07:23:53 UTC. The managed service recorded kernel `oom-kill` and
the guard exited 137 after 831 seconds. Its memory cap was 3,072 MiB and swap
was disabled. The final heartbeat before the kill was at height 224,471 with
RSS 2,972 MiB, 1,691 undo records, and `pk` accounting of 824,666 entries,
917,504 capacity, and 39,458,522 key bytes. The last log and status heights
were 224,627 and 224,554; they are separate observations, not a single
authoritative tip sample.

An existing durable v4 checkpoint at height 222,780 had hash
`00000000000003d9f88e8caa65b8cb47f4b5cec20617196417a4361447dbe972` and size
94,678,475 bytes. At approximately 07:27 UTC, the same CLI, configuration,
workers, validation checks, 3,072 MiB cap, and no-swap profile were restarted.
The only intended change for this trial is setting `MALLOC_ARENA_MAX=2` in the
managed service environment. The trial is running under process 838059; results
are pending. At 07:30:24.979 UTC, a fresh `getvalidationreport` observed height
225,216 with `assume_valid_checkpoint: null` and
`historical_scripts_required: true`. `getblockhash(222780)` still matched the
existing checkpoint hash. The process identity was PID 838059, start tick
2569816, with `MALLOC_ARENA_MAX=2` and no `GLIBC_TUNABLES` or `LD_PRELOAD`; the
3,072 MiB cap remained in place, swap was disabled, and OOM events were zero.
Recovery replayed 1,936 stored bodies; first sync reached height 224,695. This
first fresh report is beyond the prior status height 224,554 and last log
height 224,627, but it is not a long-term survival result. At 07:32:05 UTC,
height was 226,301; anon memory was 1,887,035,392 bytes, file memory
1,269,161,984 bytes, current cgroup memory 3,181,801,472 bytes, and OOM events
remained zero. These observations do not establish allocator causality or a
memory or speed benefit.

A finite local watcher is armed for both height >=235,216 and at least 831
seconds after the 07:30:24.979 UTC fresh report (not before 07:44:15 UTC), with
a maximum one-hour window. It tracks the same process, configuration, and
validation policy; its result is pending. A new checkpoint match and restart
will require separate evidence. Full mainnet IBD remains incomplete.

The GNU C Library manual says `glibc.malloc.arena_max` supersedes
`MALLOC_ARENA_MAX`, sets a numeric limit on arenas independent of CPU count,
and defaults to 0, which uses the number of online CPUs. This documents the
knob being tested; it does not establish that arena proliferation caused the
baseline OOM. The manual lists 8 as the 64-bit default for the separate
`arena_test` tunable, not as an 8× arena limit. See the official
[GNU C Library memory-allocation tunables](https://sourceware.org/glibc/manual/latest/html_node/Memory-Allocation-Tunables.html).

The comparison must wait for a sufficiently long same-workload observation.
Until then, the arena setting remains a hypothesis test. Preserve the same
consensus checks and resource cap; do not infer a memory benefit or throughput
change from the restart alone. Full mainnet IBD remains incomplete.

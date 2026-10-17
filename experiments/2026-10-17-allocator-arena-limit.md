# Allocator arena limit during managed mainnet IBD

**Status:** a baseline OOM is verified, and a finite same-process survival
observation and one clean checkpoint/restart proof under the arena limit
passed. This does not establish allocator cause, memory win, speed result, or
completed-IBD conclusion.

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
managed service environment. The trial ran under process 838059. At
07:30:24.979 UTC, a fresh `getvalidationreport` observed height
225,216 with `assume_valid_checkpoint: null` and
`historical_scripts_required: true`. At recovery,
`getblockhash(222780)` matched the existing checkpoint hash. The process
identity was PID 838059, start tick
2569816, with `MALLOC_ARENA_MAX=2` and no `GLIBC_TUNABLES` or `LD_PRELOAD`; the
3,072 MiB cap remained in place, swap was disabled, and OOM events were zero.
Recovery replayed 1,936 stored bodies; first sync reached height 224,695. This
first fresh report is beyond the prior status height 224,554 and last log
height 224,627, but was not by itself a long-term survival result. At 07:32:05
UTC, height was 226,301; anon memory was 1,887,035,392 bytes, file memory
1,269,161,984 bytes, current cgroup memory 3,181,801,472 bytes, and OOM events
remained zero.

The finite watcher sampled from 07:31:53.569 UTC (checked height 226,023)
through 07:48:53.630 UTC (235,252), at 30-second intervals.
The interval from the 07:30:24.979 UTC recovery proof to the final observation
was 1,108.649 seconds; checked height advanced 10,036 blocks, from 225,216 to
235,252. At recovery, `getblockhash(222780)` matched the initial durable
checkpoint; that older hash was not polled throughout the watcher.
Full-validation policy was checked throughout the watcher and
remained `assume_valid_checkpoint: null` with
`historical_scripts_required: true`. The collected samples reported zero OOM
and OOM-kill events. Sampled maxima were 2,239,561,728 anon bytes, 2,191,588 KiB process RSS,
and 3,221,221,376 bytes cgroup current. The current-memory maximum was within
4 KiB of the 3 GiB cap; at that sample, about 1 GiB was file cache. The
`memory.events.max` counter reached 103,613, so this observation shows continued
resource pressure, not generous headroom. It is a finite same-process survival
observation, not a matched causal comparison: it does not show that the arena
setting caused survival or reduced memory, and it provides no speed result.

The arena-2 CLI stopped cleanly with exit code 0 before the checkpoint capture.
The v4 checkpoint was captured at 07:50:05.520 UTC at height 235,517 with hash
`00000000000000e9d96b9ca5ca7e865070f55414049732fe5a5919c37099e050`, size
95,646,575 bytes, and framed SHA256d verified. The file SHA-256 was
`99da068833c6a00a91ad7db2e29d30b10e29182a20216d7331cccd0183ac0262`. At
07:51:22.934 UTC, a new process (PID 943399) resumed at checked height 235,847
and reported the same hash for saved height 235,517. Its actual environment had `MALLOC_ARENA_MAX=2`,
the same CLI/configuration and full-script validation policy, a 3,072 MiB cap,
and swap disabled. This proves checkpoint continuity across this clean
restart; it does not establish persistent lifetime, full IBD completion, or
allocator causality. Full mainnet IBD remains incomplete.

The GNU C Library manual says `glibc.malloc.arena_max` supersedes
`MALLOC_ARENA_MAX`, sets a numeric limit on arenas independent of CPU count,
and defaults to 0, which uses the number of online CPUs. This documents the
knob being tested; it does not establish that arena proliferation caused the
baseline OOM. The manual lists 8 as the 64-bit default for the separate
`arena_test` tunable, not as an 8× arena limit. See the official
[GNU C Library memory-allocation tunables](https://sourceware.org/glibc/manual/latest/html_node/Memory-Allocation-Tunables.html).

The finite observation and restart proof do not isolate allocator behavior
from other workload or allocator-state differences. Preserve the same
consensus checks and resource cap; do not infer a memory benefit or throughput
change from these observations. Full mainnet IBD remains incomplete.

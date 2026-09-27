**Full Bitcoin IBD: physical limits, machine limits, and the next experiments**

Date: 2026-09-26. Status: analysis plus bounded arithmetic probes, not a
full-history benchmark. This supplements the
[execution audit](../docs/IBD_EXECUTION_AUDIT_2026-09-26.md) and replaces the
quantitative floor claims in the earlier [physics proposal](2026-09-26-ibd-physics.md).
The [researcher work order](../docs/IBD_RESEARCHER_WORK_ORDER_2026-09-26.md)
assigns further measurements to SWE-2.

**Conclusion**

There is no established universal ten-minute physical floor. There is also no
evidence here that an arbitrary modern machine can fully validate Bitcoin at its
network's line rate. The strongest useful answer is a resource budget for a
specified computer, a specified corpus, and specified validation semantics.

On the inspected i3-N305, short canonical ECDSA probes took roughly 100–135
microseconds of CPU time per attempt including compressed-key parsing. If there
were 1.5 billion such attempts, ideal eight-core division gives 5.2–7.0 hours for
that algorithm's signature work alone. This is an extrapolation, not a physical
minimum, a sustained multicore measurement, or a count of historical signatures.

For a different machine, a ten-minute full-check target requires, under the
earlier proposal's assumed workload, at least 2.5 million ECDSA attempts/second,
1.28 GB/second of raw corpus ingress, and 4.5 million state events/second,
concurrently with hashing, script execution, and materialization. A five-minute
target doubles those demands. Nothing derived here establishes an impossibility
at either deadline. Neither deadline is established as achieved.

One concrete limit on this particular computer is the NVMe link: sysfs reports
8 GT/s, four PCIe lanes. With PCIe Gen3's 128/130 line coding, its coding-only
capacity is 3.938 GB/s per direction, before transaction overhead. Reading an
assumed 768 decimal GB from that drive therefore needs at least 195 seconds,
even with instantaneous computation and an ideal SSD. This applies to that
uncompressed, cold, single-drive input path; compression or another input path
changes the premise.

**What “full validation” and “floor” mean**

Fix a Bitcoin mainnet height and hash. Start without trusted historical script
verdicts or an assumed UTXO state. Check every applicable consensus condition,
authenticate every prevout, and produce the exact final UTXO state and a fully
completed validation frontier. Network/rule parameters and header admission's
local-time context must also be fixed; the corpus does not supply those.
Distinguish a pruned validator from an archival node and state whether the final
result must be durable. Fetching or producing auxiliary data counts when the
scenario requires it.

Three different quantities must not be called the same thing:

- A physical or interface bound excludes schedules that cannot move or process
  the required information within the specified hardware budget.
- An implementation bound counts instructions, transfers, and dependency depth
  for a particular algorithm on a particular machine. Another representation or
  algorithm can invalidate it.
- An achieved benchmark establishes a feasible runtime for its measured scope.
  It is an upper bound on the best attainable time, not proof that faster is
  impossible.

An isolated stage measured at its maximum throughput is not automatically a
capacity that remains available when all stages run together.

**At the actual physics level**

There is no fixed number of minutes without limits on area, power, memory,
interconnect, and allowed initial information. More independent arithmetic
engines reduce elapsed time without removing checks. A fixed already-known
corpus could even be encoded into prior knowledge; exclude that when defining
fresh independent validation. The operational question concerns an untrusted
input and an ordinary cryptographic verification model.

Landauer's principle bounds dissipated energy when information is irreversibly
erased. At 300 K, kT ln(2) is about 2.87e-21 joules per erased bit. Hypothetically
erasing each of 768 billion bytes once would give about 17.6 nanojoules. Reading a
byte is not necessarily erasing it, and this is not the energy budget of Bitcoin
validation. A computation's erased information and physical implementation have
to be specified. The principle supplies no useful ten-minute result.
[Primary thermodynamics paper](https://www.nature.com/articles/ncomms8669).

Light takes about a nanosecond to cross 30 cm in vacuum. Real wires, gates,
clocking, voltage margins, capacitance, and heat removal set much slower
practical limits. Dynamic switching power scales approximately with activity
times capacitance times voltage squared times frequency. Lower voltage can
improve energy efficiency while reducing attainable clock speed; more parallel
lanes consume area and power. None of these quantities were established for a
custom Bitcoin validator, so an ASIC-level time floor would be invented.

The relevant practical bounds are instruction issue, arithmetic dependency
depth, memory traffic and latency, storage/link capacity, and thermal throughput.
There is no supplied proof that historical ECDSA verification requires one
particular linear number of group operations under every possible algorithm.
Reading untrusted records imposes work in the usual model; it does not prove a
universal wall-clock threshold.

**The dependency graph is more permissive than the original proposal**

An ordering constraint is not the same as a requirement to execute a serial
transaction loop. With all headers available, their hashes and PoW checks can
be computed independently; predecessor links are then compared. MTP uses short
windows. Cumulative work admits a prefix scan. Difficulty and deployment
context still have to be derived correctly, but headers do not intrinsically
require hashing one header only after the preceding header finishes.

For transaction work, authenticated source-output data lets script tasks run
ahead of state mutation. Acceptance still waits for every provenance, ordering,
value, script, and block-level condition. General scripts can make later
signature attempts depend on earlier results, so arbitrary script execution is
not one pre-extractable list of independent successful signatures. The common
case can be specialized without discarding these dependencies.

Real serial chains exist inside algorithms: SHA-256 compression state flows
between consecutive chunks of one message, point doubling depends on the
previous point, and carry chains connect limb operations. Those are different
from serializing the entire historical chain. Large numbers of independent
messages and points can hide their latency.

A general lower-bound model for a fixed implementation is:

    T >= max(critical_path,
             incoming_bytes / incoming_capacity,
             outgoing_bytes / outgoing_capacity,
             disk_read_write_service_demand,
             DRAM_bytes / sustainable_DRAM_bandwidth,
             demand_on_each_instruction_resource / its_capacity)

If stage s consumes d[s,r] units of resource r, the resource demand is the sum
over stages, not the maximum individual demand. For CPU stages on c equivalent
cores, their CPU-seconds add before division by c. Distinct execution units can
overlap where their dependency graph and shared front end permit it. Queueing,
load imbalance, startup, drain, synchronization, and persistence add practical
cost beyond the optimistic bound.

**The machine actually inspected**

Read-only inspection found:

| Property | Observation |
| --- | --- |
| CPU | Intel Core i3-N305, eight logical CPUs, no SMT |
| ISA flags | SHA-NI, AVX2, BMI2, ADX; no AVX-512 or AVX-512 IFMA |
| L1 data cache | 32 KiB per core; 64-byte cache lines |
| L2 | 2 MiB per four-core cluster |
| L3 | 6 MiB shared |
| Installed memory reported by Linux | 32,175,188 KiB |
| NVMe | Samsung SSD 990 EVO Plus 1TB |
| Negotiated NVMe link | 8.0 GT/s, width 4 |
| Display device exposed in sysfs | Intel integrated device; no discrete GPU observed |

Intel lists a single memory channel and up to DDR4-3200 or DDR5-4800 for this
processor family. A 64-bit data channel at those rates has theoretical payload
bandwidth of 25.6 or 38.4 GB/s respectively. Installed memory type/rate and
sustainable bandwidth were not measured. Do not use those ceilings as achieved
rates. Eight workers share the memory channel.
[Intel product brief](https://cdrdv2-public.intel.com/763908/n-series-i3-product-brief.pdf).

Single-core turbo is not a sustained all-core clock. CPU-time measurements
remove time spent descheduled, but do not remove frequency variation, cache
interference, or thermal effects. This host was actively doing other work.

**Measured arithmetic, before any proposed replacement kernel**

The probe reused an existing canonical trace from 24 linked mainnet blocks,
heights 956105–956128. It did not read a live chainstate or reconstruct
historical prevout provenance. The original replay used supplied undo/prestate.
Its trace contains 32-byte messages, normalized compact signatures, compressed
public keys, and the expected Boolean result. Historical DER parsing, original
key encodings, sighash construction, interpreter work, and state validation
are outside this probe.

The whole trace contains:

- 183,782 ECDSA attempts: 177,645 true and 6,137 false.
- 183,782 distinct message/signature/key tuples.
- 97,304 distinct compressed public keys.

A false ECDSA comparison need not mean an invalid block: CHECKMULTISIG can try
more than one key before matching. Counting inputs, signatures, attempted
comparisons, and successful comparisons as interchangeable gives a false cost
model. This trace also says nothing about total historical Schnorr work.

For 512 evenly spaced trace records, both the instrumented and ordinary builds
reproduced every recorded verdict, including 23 false results. Counters were
inserted into a private copy of the pinned secp256k1-sys 0.10.1 dependency.
Timings used the unmodified dependency. No node code or registry source was
edited. All probe processes used CPU 7, nice increment 19, and bounded execution.

| Mean operations per attempted verification | Compressed parse + verify | Already parsed key/signature |
| --- | ---: | ---: |
| Field multiplication | 984.707 | 970.707 |
| Field squaring | 972.604 | 717.604 |
| Field square root | 1 | 0 |
| Scalar inversion modulo group order | 1 | 1 |
| Variable-time field inversion | 0 | 0 |
| Point-doubling function calls | 128.387 | 128.387 |
| Mixed-add function calls | 50.258 | 50.258 |
| Z-inverse-aware add function calls | 16.973 | 16.973 |
| Scalar multiplication function calls | 5 | 5 |

Point-call counts include special-case paths; they are not all equal-cost
nondegenerate additions. The first column includes normalized compressed-key
parsing even when the original on-chain encoding may have differed.

An initial generic build measured 131.49 microseconds/attempt including parsing
and 117.62 with parsing already done. A later native-target build measured
105.36 and 92.02. A short A/B/B/A follow-up yielded:

| Build | Parse + verify median CPU microseconds | Preparsed median |
| --- | ---: | ---: |
| Generic A | 104.49 | 91.04 |
| Native B | 104.67 | 93.05 |
| Native B | 100.91 | 87.36 |
| Generic A | 112.82 | 101.72 |

Consequently there is **no established compiler speedup**. The initial apparent
gain was confounded by changing machine conditions. These runs give a cost
scale and exact arithmetic census, not sustained throughput or benchmark
confidence intervals.

Raw commands, hashes, outputs, census, disassembly instruction summaries, and
conditional arithmetic are in
[the results JSON](results/2026-09-26-ibd-hardware-floor.json).
The isolated source is [ibd_cost_probe.c](code/ibd_cost_probe.c), driven by
[ibd_hardware_probe.py](../tools/ibd_hardware_probe.py).

**From elliptic-curve equations to integer instructions**

ECDSA checks a relation involving R = (z/s)G + (r/s)Q. Scalar arithmetic is
modulo the group order n. Point coordinates use
p = 2^256 - 2^32 - 977. Those are different modular arithmetic problems.
Calling both inversions “field inversion” obscures the actual work.

The pinned verifier uses five 52-bit limbs in 64-bit words for a field element.
That occupies 40 bytes, not 32. Scalars use four 64-bit limbs. A Jacobian point
has three field coordinates and an infinity representation. Intermediate
representations intentionally permit bounded excess magnitude to defer
normalization; correctness depends on those bounds.

For a field product, 2^256 is congruent to 2^32 + 977 modulo p, allowing high
bits to fold into low limbs. This replaces general division, but still needs
wide products, additions with carries, shifts, and final normalization.
Four 64-bit limbs reduce the schoolbook cross-product count but can create
harder carry scheduling. Five 52-bit limbs leave headroom but do more products.
Vector and scalar machines can favor different representations.

The sampled algorithm used roughly 985 field multiplies and 973 squares per
attempt. The generic inner multiplication compiled to 31 MUL instructions;
the square compiled to 21. Both contained eight 64-bit SHRD instructions.
The native build replaced the generic multiplication instructions with MULX
and reduced some moves, but retained the SHRDs. A specialized multiply clone
had a slightly different instruction mix.

Multiplying those generic body counts by the arithmetic census suggests about
50,951 machine multiply instructions and 15,658 SHRD instructions per attempt
in these field primitives alone. This is an instruction-demand model, not a
hardware-counter measurement of the complete dynamic instruction stream.

Intel's Gracemont table lists reciprocal throughputs of one cycle for MUL r64,
0.5 cycles for MULX r64, and twelve cycles for SHRD r64 with an immediate.
These are an excellent reason to inspect the generated reduction code.
Replacing a wide shift with separately scheduled shifts and ORs may matter
more on this machine than on a large desktop core. Confirm the actual stepping,
instruction forms, dependency behavior, and dynamic paths before using that
table to announce a floor.
[Intel instruction timing table](https://cdrdv2-public.intel.com/723461/350391-Intel-Processors-Based-on-Gracemont-Microarchitecture-Latency-Throughput.pdf).

For illustration only, 15,658 shifts times twelve cycles, divided by an
optimistic 3.8 GHz, is about 49.4 microseconds/attempt of shift-resource demand.
At 1.5 billion attempts and eight cores that would be 2.58 hours under that
schedule model. It is a bound on a retained instruction sequence under the
specified model, not on ECDSA: changing the sequence removes the premise.
The short SHA probe also illustrates why published scheduling values need
target-machine confirmation rather than blind extrapolation.

MULX avoids the implicit result-register constraints of MUL and leaves flags
available for independent carry work. ADCX and ADOX can maintain separate carry
chains. That helps only if multiplication ports, registers, and the scheduler
can exploit the resulting independence. Assembly must be evaluated on dependency
depth, reciprocal throughput, port pressure, spills, and instruction delivery,
not source-level operation counts alone.

The actual point-doubling formula here uses three field multiplications and
four squares. The verifier uses scalar splitting, sparse signed digits, and
precomputation; the final x-coordinate comparison avoids an affine inversion.
Its G tables occupy about 1 MiB with the selected window. Shared L2 capacity,
per-key tables, and table access patterns therefore matter.
[Upstream multiplication design](https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_impl.h)
and [ECDSA verification](https://github.com/bitcoin-core/secp256k1/blob/master/src/ecdsa_impl.h)
provide context; the operation counts above come from the locally pinned version.

**Four distinct ways to reduce signature cost**

First, reuse exact work. Cache parsed public keys and useful bounded
precomputation by exact key identity. The existing trace has approximately
1.89 attempts per distinct key on average, with substantial skew. A cache's
memory cost and locality matter: storing every key's expanded table can evict
the hot fixed tables. Sorting or coalescing jobs by key can improve locality,
but its movement and latency costs belong in the benchmark.

Second, supply cheaper-to-check information. A compressed key's y coordinate
normally requires a square root. An untrusted helper can provide y, and the
receiver can check canonical bounds, the original parity bit, and
y^2 = x^3 + 7. For valid secp256k1 points, that verifies the same chosen root
without computing it by exponentiation. The full original encoding checks
still apply. The measured parse delta was 14 field multiplications and 255
squares per attempt. Merely assuming the helper's y is correct is forbidden.

This trades bandwidth/storage for compute: one extra 32-byte y per 1.5 billion
attempts would be 48 GB before deduplication; one per distinct key can be less.
The right choice depends on link speed and compute. A warm local key cache
provides a similar reuse opportunity without additional network bytes.
This is a concrete example of acceleration by verified representation.

Third, batch scalar inversions. For k nonzero scalars, the standard prefix/
suffix construction uses one inversion and about 3(k-1) multiplications.
Zero/out-of-range scalars and malformed inputs require the original rejection
semantics. There is one inversion per sampled attempt to target, not two
field inversions. Its actual runtime share determines the benefit; no 10–15%
saving follows just from the formula. Bounded batches are preferable to storing
every scalar in the entire history.

Fourth, replace the verification algorithm or its hardware mapping.
Nonce-point advice and multi-scalar multiplication may change work counts.
Randomized aggregate acceptance changes the error model and must be explicitly
audited; it cannot silently stand in for exact per-attempt verdicts. Failed
comparisons, malformed hints, and fallback localization still count.
Existing advice measurements are useful candidates, not multiplicative factors
that can simply be stacked onto a GPU forecast.

**SIMD and GPU budgets**

AVX2 lacks a direct packed 64-by-64-to-128-bit integer multiply. An implementation
can use smaller limbs and partial products, but carry handling and extra
instructions can absorb much of the nominal lane count.

AVX-512 IFMA handles 52-bit products accumulated into 64-bit lanes, with separate
low/high product instructions. A straightforward five-by-five-limb product
requires 25 limb pairs; accounting for both halves gives roughly 50 vector
multiply-add instructions for eight independent elements before reduction.
Squares can use symmetry. Eight lanes do not imply eight times the best scalar
throughput, especially when instruction issue width and vector frequency differ.

Keep independent signatures in lanes and lay out limbs by lane. Account for
the transpose from incoming records, table gathers, masks, register pressure,
and tails. Sparse scalar digits differ between signatures. A lockstep kernel
can waste work on inactive lanes, while grouping/reformatting work introduces
other costs. The inspected machine cannot execute IFMA, so testing that kernel
requires another machine, not a compiler flag.

On GPUs, modular integer multiplication is the relevant primitive; advertised
floating-point or tensor throughput does not measure it. Compare one signature
per thread with cooperative limb arithmetic across threads. The former spends
registers; the latter spends communication and synchronization. Inspect carry
chains, register spills, occupancy, divergence, and coalesced accesses in the
generated machine code. NVIDIA's Ada guide gives a 64K 32-bit register file per
SM and documents occupancy and memory-layout constraints.
[NVIDIA tuning guide](https://docs.nvidia.com/cuda/ada-tuning-guide/index.html).

Even a compact GPU record with a 32-byte message, 64-byte signature, and 33-byte
key is 129 bytes: 193.5 GB for 1.5 billion attempts. Count host preparation,
layout conversion, PCIe transfers, queueing, device execution, and result
consumption separately and together. Sending the whole block corpus is a
different design with different traffic. SHA offload shares the GPU's resources;
it is not free because a signature kernel happens to be present.

An author-hosted community table for UltrafastSecp256k1 reports 8.14 million
ECDSA verifications/second on an RTX 5070 Ti. That is a relevant lead, not
independently reproduced evidence: benchmark input diversity, full equations,
consumption of results, timed boundaries, transfer inclusion, source revision,
and negative cases must be checked. The benchmark source URL was not retrievable
during this audit. Do not adopt the figure as a Bitcoin IBD capacity.
[Reported GPU benchmark](https://github.com/shrec/UltrafastSecp256k1/blob/main/docs/COMMUNITY_BENCHMARKS.md).

A mining ASIC is not a general ECDSA engine or arbitrary-message SHA service.
A custom verification ASIC or FPGA could implement different datapaths,
register memories, and pipelines. For an engine taking D cycles at clock f,
q independent engines have ideal throughput q*f/D. The missing quantities are
area, routing, memory service, utilization, and power; no design was synthesized
here. More hardware is a valid path below a software deadline without changing
consensus or using a succinct chain proof.

**SHA work must be counted in compression calls**

For a fresh SHA-256 message of L bytes, the compression count is
ceil((L+9)/64). Double-SHA256 adds one compression for the 32-byte first digest.
A 64-byte Merkle pair therefore costs three compressions, not one. An
80-byte block header also costs three. A cached prefix or a specialized kernel
changes which work can be reused and must be accounted for explicitly.

SHA-NI's SHA256RNDS2 instruction performs two rounds of one SHA state. A full
compression needs 32 such instructions plus schedule generation, data movement,
and feed-forward. Using XMM operands does not mean it hashes several independent
messages in parallel. Interleaving separate states can hide latency.
[Intel SHA instruction description](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html).

A tiny fixed-message round-only probe measured median CPU costs between about
0.36 and 0.44 ns per instruction with four interleaved states, compared with
about 1.05–1.35 ns with one. It omitted schedules, padding, real buffers, and
complete hashing. Converting the four-state result gives about 4.6–5.6 GB/s
of compression-block-equivalent work before the omitted costs. This is neither
an actual hash throughput nor a proven hardware ceiling.

Txid, wtxid, legacy sighash, witness sighash, and Merkle work are different
message distributions. The important counts are actual compression calls
after safe reuse, message lengths, common prefixes, and available independent
states. BIP143 and BIP341 explicitly permit reusable transaction components.
Legacy sighash needs its exact consensus semantics, including special cases;
an arbitrary cached digest cannot replace a different preimage.
[BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki),
[BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).

Sighash “input bytes” can exceed DRAM traffic because shared bytes stay in cache
or registers; DRAM traffic can exceed corpus size because of parsing, copying,
and intermediate records. Use separate counters. A promise that every byte is
physically touched once is not a useful machine model.

Even hash-chain dependency depth can change when the input includes checked
advice. An untrusted producer can supply intermediate SHA states at segment
boundaries. Workers recompute every segment from its supplied starting state,
compare each result with the next boundary state, and check the original initial
state and final digest. With complete segment coverage and correct padding/
length handling, every transition is checked and consistency follows across
the whole message. This retains the hashing work while permitting parallel
segment verification. It adds hint bytes, scheduling, and comparison work.
Fine-grained hints are expensive; coarse boundaries can be economical.

That is another reason to specify the permitted input representation before
claiming an unavoidable serial floor. Existing snapshot-midstate experiments
can inform this design, but do not automatically establish a benefit for the
much shorter transaction/sighash message distribution.

**State representation is a major architectural opportunity**

The consensus problem needs authenticated creation identity, legal spend
ordering, uniqueness, amounts/scripts, and the correct survivor set. A map keyed
by 36-byte outpoints is one representation of that information.

If 1.5 billion output occurrences have dense locally established IDs, a single
spent bitmap costs 187.5 MB. Two bits per occurrence cost 375 MB. The arithmetic
does not include the directory mapping IDs to authenticated outputs, scripts,
amounts, metadata, or final UTXOs. Those must be supplied, recomputed, stored, or
looked up; the bitmap alone is not a stateless validator.

An untrusted positional hint can identify the source transaction/output. Verify
its exact txid/vout against the input, reconstruct the authenticated amount and
script, establish the correct output occurrence and creation position, and then
use the dense ID for exact spent tracking. Test-and-set needs synchronization,
or partition ownership that prevents two workers from accepting the same spend.
Partitioning by output ID avoids contending on shared bitmap words.

Historical duplicate txids/overwrites make occurrence identity essential.
Same-block spends are allowed only after creation. Coinbase maturity allows
exactly 100 blocks of depth. BIP30 pre-block behavior and exceptions, genesis,
provably unspendable outputs, finality, relative locks, per-block fees/subsidy,
and all script rules remain necessary. An event stream sorted by identity and
position can express this, but a bare set difference cannot.
[BIP30](https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki),
[BIP68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki).

This gives two useful designs to compare: exact partitioned event joins and
authenticated dense-position tracking. Neither requires a probabilistic
multiset sum to be the only correctness check. The current SwiftSync and
Utreexo prototypes need the repairs in the execution audit before they can be
substituted for exact state validation.

Record width matters. At 2.7 billion events:

- 36-byte outpoint identity alone is 97.2 GB per pass.
- Writing and rereading those keys is 194.4 GB.
- Adding metadata, scripts, partitions, source data, output, and durability
  increases traffic. Dense IDs can reduce it after their construction is priced.

On this CPU a 64-byte cache line can contain 512 bitmap bits. A random bit
update can still acquire and dirty an entire line. Ordinary cached stores may
require ownership traffic and eventual writeback. Multiple cores touching
different bits in the same line can bounce ownership between caches.
Partitioning, local aggregation, and appropriate streaming writes can be more
valuable than fewer arithmetic instructions.

For random reads with latency L, M outstanding misses, and q useful bytes per
miss, useful throughput cannot exceed M*q/L. With a dependent pointer chain,
M may be near one even on an eight-core machine. As an illustration, a
100 ns dependent miss permits only ten million dependent steps/second; a tree
with multiple misses per lookup makes that worse. That 100 ns is an example,
not a measurement of this computer.

The corresponding disk problem is more extreme: fetching one small record can
cause a 4 KiB page read. Random IOPS, queue depth, page cache, writeback, and
amplification then govern throughput. An external join can replace many random
accesses with sequential passes, but it cannot omit its extra bytes or claim
that a hot tiny fixture represents a memory-constrained laptop.

**Compression and locality change the budget**

The wire size and the logical decoded corpus size need not match. Outpoints can
be represented by references to previously established transactions; repeated
scripts and keys can use dictionaries; predictable structure can be generated.
Every original consensus-relevant byte must be reconstructed exactly when
needed. Legacy noncanonical encodings require lossless escape paths.

Calling cryptographic bytes “incompressible by definition” is unjustified.
Entropy depends on the information already available and on the allowed
decoder. A txid is derived from its transaction, not independent new information
when that transaction is already present. Compression can save transmission
while increasing lookup, hashing, or decode work. No 25% universal ceiling was
established. Measure the actual byte categories and a lossless codec.

The most useful fusion is often between producer and immediate consumer:
parse a bounded buffer, derive transaction components, form signature jobs,
and release raw bytes when their consumers finish. Fusing everything into one
thread can sacrifice more parallel throughput than the saved copies are worth.
Use bounded queues and choose where buffers live according to cache capacity
and backpressure. Do not force a whole-corpus in-memory design.

**Quantitative targets, with every assumption exposed**

The following is arithmetic using the earlier research's unverified workload
assumptions: 768 decimal GB of raw input, 1.5 billion ECDSA attempts, and
2.7 billion state events. It is not a current Bitcoin census. Schnorr work,
script interpretation, final state, and additional reads/writes still need
their own measured demand.

| Deadline | Raw ingress | ECDSA attempts/s | State events/s | Per-core budget per ECDSA attempt, 8 cores |
| --- | ---: | ---: | ---: | ---: |
| 60 min | 0.213 GB/s | 416,667 | 0.75 million | 19.2 microseconds |
| 30 min | 0.427 GB/s | 833,333 | 1.50 million | 9.6 microseconds |
| 20 min | 0.640 GB/s | 1.25 million | 2.25 million | 6.4 microseconds |
| 10 min | 1.280 GB/s | 2.50 million | 4.50 million | 3.2 microseconds |
| 5 min | 2.560 GB/s | 5.00 million | 9.00 million | 1.6 microseconds |
| 1 min | 12.800 GB/s | 25.00 million | 45.00 million | 0.32 microseconds |

The last column generously assigns every CPU cycle to ECDSA. A real CPU-only
validator must reserve capacity for the other tasks. Likewise, a GPU meeting
the signature column does not establish the complete node's deadline.

If the work census eventually finds three TB of normalized SHA compression
bytes, a ten-minute target additionally requires five GB/s of that work and a
five-minute target ten GB/s. The three-TB input remains an assumption; it must
not be confused with three TB of source bytes or actual measured hashing.

For raw 768 GB ingress alone, before overhead:

| Payload link rate | Minimum transfer time |
| --- | ---: |
| 100 Mbit/s | 17 h 4 min |
| 300 Mbit/s | 5 h 41 min 20 s |
| 1 Gbit/s | 1 h 42 min 24 s |
| 2.5 Gbit/s | 40 min 57.6 s |
| 10 Gbit/s | 10 min 14.4 s |

For fixed validation throughput, slower links are easier to keep up with.
The line-rate crossover is B/T_validate, with consistent units and the actual
transmitted representation. A ten-minute raw-corpus sync cannot fit into a
ten-Gbit/s payload link under these assumptions, regardless of assembly.

**What this changes in the program**

Retain the live-path fixes and exact correctness boundaries already assigned
to the active agent. Assign the researcher a corpus work census, machine
capacity model, and isolated replay/state prototypes with explicit accounting.
Prioritize the N305 shift/reduction sequence, repeated-key reuse and checked
key-expansion hints, bounded scalar inversion, and representation/locality
before assuming a particular SIMD multiplier.

For a desktop GPU, test the throughput required by the target deadline rather
than a vague “60–100x” promise. For a small machine, optimize the amount of
information moved and the cost of each repeated primitive. An assembly rewrite
is justified when generated instructions and measurements identify a specific
inefficiency. A whole-node rewrite in assembly has no established benefit.

Further experiments belong to SWE-2. Codex's next role is to audit the supplied
revision, raw measurements, accounting, and correctness evidence against this
model.

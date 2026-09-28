# Review of the proposed crypto ceiling and assembly direction

The saved evidence does not establish a 1.9x, 2.2x, or 3x ceiling. Several
measurements do not measure the work their labels describe. This also does not
establish that a larger gain is achievable. The useful next step is a small
comparison of corrected kernels and schedules, before committing to a new
assembly verifier.

This review applies to the source hashes in
[the receipt](results/2026-09-27-crypto-ledger-review/review.json), not to
unarchived binaries or later revisions. No production code was changed.

## Evidence that changes the decision

1. **The AVX2 rejection rests on an incorrect archived kernel.** Running the
   original 4,000-group correctness section, with only the timing section
   removed, produced **15,004 failed lanes out of 16,000**. The run used
   `tools/guard_run.sh --max 512 --reserve 4096` and a 20-second timeout;
   exit 1 is the test reporting mismatches. The archived kernel reduces at
   bit 260 but `tenx26_to_bytes` discards bits 256 through 259. Those bits
   must be folded using `2^256 = 2^32 + 977 (mod p)`. The first discrepancy
   is exactly `7 * (2^32 + 977)`. The timing recurrence also grows `va[0]`
   outside the stated 26-bit input bounds and lacks a final output consumer.
   This is evidence against this probe, not against the AVX2 design space.
   Source: [femul4_avx2_bench.c](code/femul4_avx2_bench.c).

2. **The 1.19x merged comparison charges different work.** At lines 184–188,
   the candidate prepares all wNAF digits, odd-multiple tables, global-Z
   transformations and beta auxiliaries before timing. The scalar timed
   loop calls full `ecmult`, including that preparation, while the candidate
   calls only `ladder4`. The scalar loop changes scalars; the candidate
   changes a point-table x limb without updating its y or beta auxiliary.
   The four initial output comparisons do not validate the subsequent timed
   inputs. This cannot establish a matched `ecmult` or verification speedup.
   Its extra doubling benchmark also starts every lane with `inf=1`, so
   `dbl` immediately returns. Source:
   [ecmult4_merged_bench.c](code/ecmult4_merged_bench.c).

3. **The FMA throughput numerator is wrong for the generated code.** With
   GCC 15.2, `-O3 -mbmi2 -mavx2 -mfma`, the eight identical FMA chains
   collapse to one chain. The loop is unrolled twice: two dependent FMAs,
   then decrement by two. The integer loop retains two multiplies per
   iteration; its other six results are unused. Both printed numerators
   still charge eight operations per iteration. They also assume a fixed
   2.9 GHz. The quoted 1.51 vector FMAs/cycle and comparison with integer
   multiply are unsupported. Inspect the saved
   [main assembly](results/2026-09-27-crypto-ledger-review/fma_tput_bench.main.s).

4. **The claimed register-residency explanation is unproven.**
   `dbl4_locals_bench.c` consumes none of the resulting points, initializes
   some lanes outside the field-operation bounds, and has excess scalar
   initializer elements. Generated code inlines much of the four-lane case
   but calls `dbl` in the serial case. That mixes several effects. Four
   Jacobian points alone contain 60 64-bit limbs in 5x52 representation,
   before temporaries; named C locals do not make these all resident in
   general-purpose registers. A useful comparison must consume every
   coordinate from distinct valid inputs and inspect both loops.

5. **Some proposed savings are already absent from the baseline.** In the
   pinned dependency, `ge_table_set_globalz` propagates known Z ratios using
   multiplications; it performs no inversion. The existing 512-attempt
   [operation census](results/2026-09-26-ibd-hardware-floor.json) records zero
   field inversions and one scalar inversion per ordinary verification.
   Scalar inversions modulo the group order can still be batched, but cannot
   share one Montgomery inversion with arithmetic modulo the field prime.
   Magnitude/normalization metadata is compiled out without `VERIFY`.
   Ordinary Strauss verification already calls variable-time point addition.
   These items cannot be priced as fresh savings in this build.

6. **The instruction model is not the emitted program.** The earlier native
   disassembly records 31 `mulx`, 31 `add`, 29 `adc`, eight `shrd`, and 82
   `mov` instructions for the generic field multiply. That is not a complete
   60-micro-op kernel. The compile audit here also finds no `ADCX`/`ADOX`
   in either the doubling or merged-ecmult translation unit. Static
   instruction counts are not dynamic micro-op counts, but the saved counts
   already contradict the proposed accounting.

## The Gracemont issue the assembly proposal missed

Intel's optimization manual, section 4.1.8.8, documents that Gracemont tracks
the arithmetic flags together. An `ADCX`/`ADOX` sequence can therefore carry
a dependency between the two instructions that larger Intel cores avoid.
Having ADX instructions does not imply the usual independent dual-carry
throughput. This does not rule out a fast 4x64 implementation; it changes
what the implementation must demonstrate.

Source: [Intel Optimization Reference Manual, volume 1, revision 049](https://cdrdv2-public.intel.com/814198/248966-Optimization-Reference-Manual-V1-049.pdf).

A finite reorder buffer is a scheduling resource, not a proof that only four
logical jobs are useful. A streamed schedule need not hold four complete
addition formulas simultaneously. More queued jobs can supply ready operations
or amortize inversions without all their instructions entering the window.
Measure front-end, execution-port, dependency and memory costs for the actual
schedule before treating one resource as the limiter.

Likewise, C can express operation-by-operation interleaving and limb-level
interleaving, especially with intrinsics or generated straight-line code.
The compiler might schedule it poorly; assembly provides tighter control.
The claim that only assembly can represent this computation is false.

Four 64-bit limbs are also possible in C using multiword accumulators and
explicit carries. They reduce the schoolbook product count, but lose the
headroom that makes additions and deferred normalization cheap in 5x52.
Price reduction, squares, additions and the point formula together. The
product-count reduction and lazy-reduction gain are not independent coupons.

## Designs worth testing

### 1. Exact FMA with wide limbs

The reported floating-point experiment uses ten 26-bit limbs. It does not
test five 52-bit limbs with exact product splitting. For suitably bounded
integer-valued doubles, a rounded product plus its FMA residual recovers the
exact wide product. Published wide-limb methods use this to obtain integer
product pieces and accumulate them with explicit bounds.

That reopens a concrete design: retain five limbs, use four SIMD lanes, split
each wide product exactly, specialize squaring, and design the secp256k1
reduction around those accumulators. Schoolbook convolution then has 25 limb
pairs instead of 100. This is a product count, **not a speedup forecast**:
each pair requires multiple instructions, and extraction, conversion,
reduction, bounds, spills and Gracemont's vector throughput must all be paid.
Rounding-mode behavior must be controlled explicitly.

Source: [Emmart, Zheng and Weems, ARITH 2018](https://www.ecs.umass.edu/arith-2018/pdf/arith25_17.pdf).
Their platform's performance is not transferable to this laptop.

### 2. Schedule ready arithmetic across independent verifications

Use a bounded tile of independent jobs, with separate verdicts. Express each
point formula as field operations and process ready operations in small
groups, rather than issuing a whole point formula from each signature in
sequence. Try tile sizes 4, 8, 16 and 32; select by measured working-set and
dispatch cost. Sparse wNAF additions can supply a compact queue of active
lanes instead of forcing every job through the same empty slots.

Start with generated C or intrinsics using the existing field representation.
This tests the scheduling hypothesis without simultaneously changing the
field representation, the arithmetic proof and the entire verification API.
Assembly is then justified for a surviving hot kernel. Compare complete point
operations and complete `ecmult`, including setup, packing and compaction.

### 3. Amortize field inversions to change coordinate costs

This is a different algorithm from batching ECDSA acceptance: run individual
computations in affine coordinates and share denominator inversions across
ready independent operations. Every signature still receives its own result;
there is no nonce advice or randomized aggregate acceptance.

For B nonzero denominators, Montgomery's trick costs one inversion plus
`3(B-1)` multiplications. An ordinary affine addition costs `I + 2M + S`,
so its amortized arithmetic is approximately
`(5 - 3/B)M + S + I/B`, before additions, normalization and scheduling.
Compare that with the pinned mixed Jacobian formula's `8M + 3S`.

This is not a free win across the ladder. Affine doubling is approximately
`(5 - 3/B)M + 2S + I/B`, against the existing `3M + 4S`; cheap squaring can
favor Jacobian doubling. Inversions at successive dependency levels,
conversion costs, sparse work, zero denominators and exceptional points all
matter. A balanced product tree avoids creating one long prefix-product
dependency chain. Benchmark full batches and preserve exact exceptional-case
handling, with the ordinary path available.

Affine identities: [Explicit-Formulas Database](https://www.hyperelliptic.org/EFD/g1p/auto-shortw.html).
The cost comparison above is derived from these identities and Montgomery's
trick, not measured here.

Repeated-key comb tables are another scoped candidate: precompute combinations
of spaced powers, rather than a 129-entry tower followed by roughly 128
additions. Include construction and cache costs and stratify by actual key
frequency. The absence of a four-dimensional cheap GLV split does not rule
out ordinary radix decomposition with paid precomputation.

## Recommended decision

Do not choose an all-new NASM `verify4` ABI yet. Repair the matched harness,
then compare a phase-interleaved kernel using existing arithmetic with an
exact wide-limb FMA kernel and the 4x64 candidate. Keep 4x64 as an experiment,
not the presumed winner. If field inversions amortize well, test the affine
batch schedule on top of the winning field kernels.

Use varying valid inputs, consume every output, compare every lane, and
include exceptional cases. Recheck the survivors on captured real signature
attempts, including false attempts, with all setup charged. Distinguish
kernel throughput, complete verification, and the full-validation wall time.
One million random matches is useful differential evidence, not a proof of
all carry bounds or consensus equivalence.

No replacement ceiling follows from this audit. Amdahl's law still applies
to a fixed baseline: if half the measured wall is affected, a 3x gain there
gives 1.5x overall, and infinite acceleration of that portion approaches 2x.
Exceeding that requires reducing the remaining wall too; it does not follow
by multiplying overlapping historical gains.

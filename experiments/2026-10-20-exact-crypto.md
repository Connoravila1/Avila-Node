# Exact crypto backend and CPU hashing iteration

Status: implemented and gated on 2026-10-20. The exact backend microbench and
fixed-message AVX2 microbench ran three times each under the guarded release
profile. A 501-block mainnet fixture smoke also completed with full validation
and matching durable UTXO commitments. These measurements do not establish a
whole-IBD speedup.

## Exact ECDSA and Schnorr backend

Consensus ECDSA/Schnorr verification uses `secp256k1 0.33.1` /
`secp256k1-sys 0.14.1` (libsecp256k1 0.8.0) through a byte-only internal
adapter. The workspace remains on its established `secp256k1 0.29.1` /
`secp256k1-sys 0.10.1` for ancillary key operations, BIP324, signing, and
test fixtures. This avoids a workspace-wide API migration while production
script checks still use the maintained binding that vendors the requested
upstream backend. The 0.8.0 changelog says force-inlining the 5x52 field
multiply and square can speed ECDSA and Schnorr verification by up to 11% with
GCC/MSVC. That upstream maximum is a hypothesis for this node, not a measured
result.

The production ECDSA path retains the same `from_der_lax` parser and explicit
`normalize_s()` call before verification. Both remain available in the new
binding. This preserves historical high-S acceptance and lax-DER parsing. A
focused test compares the new parser/normalizer with the prior binding
re-exported by the existing `bitcoin` dev dependency across canonical,
trailing-byte, truncated, malformed, and scalar-pair encodings. The existing
mainnet block 183 high-S spend remains a real historical acceptance test.

The existing `bitcoin 0.32` dev dependency also keeps the 0.29 binding in the
graph. Cargo locks both versions explicitly. No public key, signature, context,
or message object crosses between them; the adapter and differential tests
exchange only encoded bytes.

The 0.33 API changes do not reach BIP324 or other workspace APIs: those remain
on the original binding.

The guarded microbench compared the cached 0.29 ECDSA path with the production
0.33 byte-oriented path, including its parser and cache lookup. Across three
same-binary runs the median was 31,455 ns/op for 0.29 and 31,049 ns/op for 0.33
(1.3% lower for the candidate in this small synthetic benchmark). This is
directional microbenchmark evidence, not a whole-node result. The benchmark
does not include a historical block fixture's mixed script workload.

## CPU hashing candidate review

The node uses `sha2 0.11` without optional features. Its x86 SHA-256 backends
are software and SHA-NI; the target i5-9300H has no SHA-NI. RustCrypto's
maintained SHA-2 issue tracker still lists AVX2 multi-message SHA-256 as an
open exploration, so there is no such AVX2 backend to enable in the existing
crate.

The production Merkle-root path now groups complete levels into batches of
eight 64-byte child pairs and calls Bitcoin Core v31.1's fixed-message
`sha256d64_avx2::Transform_8way` through a small C ABI wrapper. It checks AVX2
at runtime and falls back to the existing `sha256d` path on older CPUs and for
partial batches. It does not alter pair ordering, odd-leaf duplication, or the
mutation check. The scalar path can be forced in the Merkle unit tests.

The vendored kernel is pinned to Bitcoin Core v31.1 commit
`9be056a8a72b624dae9623b2f7bded92c2a21c91`, includes its MIT notice, and is
otherwise unmodified. Two tiny local headers provide only the little-endian
helpers and inline macro required by this translation unit. No general SHA
implementation or other Core crypto code is imported. The adapter crate keeps
the FFI unsafe code outside the consensus crate's `unsafe_code = forbid`
boundary and exposes a checked safe function.

Focused tests compare scalar and accelerated tree results for pair and leaf
counts around the eight-way boundary, including a large odd tree, and check
that duplicate-pair mutation results remain identical. The guarded microbench
compared the scalar 8-message implementation with the Core AVX2 wrapper on
this AVX2-capable host. Across three runs, median time was 6,710 ns for eight
scalar messages and 932 ns for the AVX2 wrapper (7.2x in this isolated
fixed-message kernel benchmark). This is not a 7.2x Merkle-tree or IBD result;
tree work also includes transaction hashes, odd-level shape, allocation, and
small tails.

The 0..500 mainnet fixture run used `assume_valid=None`, all regular block and
script checks, synchronous script completion, and identical 512 MiB dbcache.
Three alternating direct-binary trials per setting finished at height 500
with 503 UTXOs and the same full `hash_serialized_3` digest. The measured block
acceptance medians were 15.5 ms for `AVILA_PREVOUT_WORKERS=0
AVILA_CLEAN_CACHE=0` and 12.0 ms for `AVILA_PREVOUT_WORKERS=2
AVILA_CLEAN_CACHE=1`. The complete fixture contains only 501 blocks / 509
transactions, and each run is shorter than 20 ms, so timing noise dominates;
these values are a functional smoke test, not an IBD speed claim. The matched
tip was `000000004ff664bfa7d217f6df64c1627089061429408e1da5ef903b8f3c77db`,
and the complete-set digest was
`9c3c4606df2ab3d7534227c3d39377382c438dda7c8dfe138ac7b1fcfbec0b23`.

The existing `sync_bench` now disables `assume_valid`, drains script work,
flushes and reopens the durable state, and checks the full UTXO commitment
before reporting success. `accept_probe` likewise compares the complete
canonical UTXO commitment before and after reopen.

## References

- [libsecp256k1 0.8.0 release](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.8.0)
- [libsecp256k1 changelog](https://github.com/bitcoin-core/secp256k1/blob/master/CHANGELOG.md)
- [rust-secp256k1 changelog](https://github.com/rust-bitcoin/rust-secp256k1/blob/master/CHANGELOG.md)
- [RustCrypto sha2 crate manifest](https://github.com/RustCrypto/hashes/blob/master/sha2/Cargo.toml)
- [RustCrypto AVX2 SHA-256 exploration](https://github.com/RustCrypto/hashes/issues/327)
- [Bitcoin Core v31.1 SHA256D64 AVX2 source](https://github.com/bitcoin/bitcoin/blob/v31.1/src/crypto/sha256_avx2.cpp)
- [Bitcoin Core v31.1 release tag](https://github.com/bitcoin/bitcoin/tree/v31.1)

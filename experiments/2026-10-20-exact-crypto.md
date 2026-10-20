# Exact crypto backend and CPU hashing iteration

Status: libsecp256k1 backend updated; performance awaits the root guarded gate.
No validation check is skipped and `assumevalid=0` remains the required run
profile. This change makes no IBD speedup claim.

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

The root gate should run the focused parser differential, the existing
`high_s_signature_verifies_mainnet_h183` test and consensus crate regression
suite, then compare matched full-validation CPU/wall results and the existing
real-fixture benchmark against the old binary. Compiler identity and release
optimization flags matter because the upstream benefit is compiler-dependent.

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
that duplicate-pair mutation results remain identical. `sha256d64` throughput
and the real fixture remain unmeasured pending the root guarded gate; no win is
claimed yet.

## References

- [libsecp256k1 0.8.0 release](https://github.com/bitcoin-core/secp256k1/releases/tag/v0.8.0)
- [libsecp256k1 changelog](https://github.com/bitcoin-core/secp256k1/blob/master/CHANGELOG.md)
- [rust-secp256k1 changelog](https://github.com/rust-bitcoin/rust-secp256k1/blob/master/CHANGELOG.md)
- [RustCrypto sha2 crate manifest](https://github.com/RustCrypto/hashes/blob/master/sha2/Cargo.toml)
- [RustCrypto AVX2 SHA-256 exploration](https://github.com/RustCrypto/hashes/issues/327)
- [Bitcoin Core v31.1 SHA256D64 AVX2 source](https://github.com/bitcoin/bitcoin/blob/v31.1/src/crypto/sha256_avx2.cpp)
- [Bitcoin Core v31.1 release tag](https://github.com/bitcoin/bitcoin/tree/v31.1)

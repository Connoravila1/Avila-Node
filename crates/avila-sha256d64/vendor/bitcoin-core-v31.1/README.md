This directory contains `src/crypto/sha256_avx2.cpp` from Bitcoin Core v31.1,
tag commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`.

The source is distributed under Bitcoin Core's MIT license. The two local
headers under `include/` provide only the `ALWAYS_INLINE`, `ReadLE32`, and
`WriteLE32` definitions used by this translation unit; they avoid importing
the rest of Core's build and crypto headers. The vendored AVX2 source itself
is unmodified.

Upstream source:
https://github.com/bitcoin/bitcoin/blob/v31.1/src/crypto/sha256_avx2.cpp

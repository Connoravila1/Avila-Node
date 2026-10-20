// Copyright (c) 2017-present The Bitcoin Core developers
// Distributed under the MIT software license.

#ifdef _MSC_VER
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE inline __attribute__((always_inline))
#endif

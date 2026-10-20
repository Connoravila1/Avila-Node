// Copyright (c) 2014-present The Bitcoin Core developers
// Distributed under the MIT software license.

#include <cstdint>
#include <cstring>

// The vendored Core kernel only uses these little-endian 32-bit helpers.
// Its AVX2 translation unit is built only for x86_64, which is little-endian.
inline uint32_t ReadLE32(const unsigned char* ptr)
{
    uint32_t value;
    std::memcpy(&value, ptr, sizeof(value));
    return value;
}

inline void WriteLE32(unsigned char* ptr, uint32_t value)
{
    std::memcpy(ptr, &value, sizeof(value));
}

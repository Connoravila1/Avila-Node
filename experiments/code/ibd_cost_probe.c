/* Isolated research probe. Never linked into the node. MIT; see NOTICE.
 * Reuses the pinned arithmetic harness; counters are inserted into a private
 * dependency copy by tools/ibd_hardware_probe.py. Timings use an unmodified copy.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
static int cost_enabled;
static uint64_t cost_counts[9];
#define main advice_probe_main
#include "ecdsa_advice.c"
#undef main
#include <immintrin.h>

static volatile uint64_t cost_sink;
static const char *cost_names[] = {
    "field_mul", "field_square", "field_inverse_var", "field_sqrt",
    "scalar_inverse_var", "point_double_calls", "point_mixed_add_calls",
    "point_zinv_add_calls", "scalar_mul"
};

static void print_counts(const char *mode, size_t n, size_t passed) {
    printf("{\"mode\":\"%s\",\"records\":%zu,\"passed\":%zu,\"operations\":{", mode, n, passed);
    for (size_t i = 0; i < 9; ++i)
        printf("%s\"%s\":%llu", i ? "," : "", cost_names[i], (unsigned long long)cost_counts[i]);
    puts("}}");
}

/* Alternating states match SHA256RNDS2's true round-to-round dependency.
 * Fixed message words deliberately omit scheduling: this is an instruction
 * experiment, NOT a SHA-256 implementation or a hashing benchmark.
 */
__attribute__((noinline)) static void sha_rounds(unsigned chains, unsigned iterations) {
    __m128i a0 = _mm_set1_epi32(1), b0 = _mm_set1_epi32(2);
    __m128i a1 = _mm_set1_epi32(3), b1 = _mm_set1_epi32(4);
    __m128i a2 = _mm_set1_epi32(5), b2 = _mm_set1_epi32(6);
    __m128i a3 = _mm_set1_epi32(7), b3 = _mm_set1_epi32(8);
    const __m128i m = _mm_set1_epi32(9);
    for (unsigned i = 0; i < iterations; ++i) {
        for (unsigned j = 0; j < 16; ++j) {
            a0 = _mm_sha256rnds2_epu32(a0, b0, m);
            if (chains > 1) a1 = _mm_sha256rnds2_epu32(a1, b1, m);
            if (chains > 2) {
                a2 = _mm_sha256rnds2_epu32(a2, b2, m);
                a3 = _mm_sha256rnds2_epu32(a3, b3, m);
            }
            b0 = _mm_sha256rnds2_epu32(b0, a0, m);
            if (chains > 1) b1 = _mm_sha256rnds2_epu32(b1, a1, m);
            if (chains > 2) {
                b2 = _mm_sha256rnds2_epu32(b2, a2, m);
                b3 = _mm_sha256rnds2_epu32(b3, a3, m);
            }
        }
    }
    a0 = _mm_xor_si128(a0, b0);
    a1 = _mm_xor_si128(a1, b1);
    a2 = _mm_xor_si128(a2, b2);
    a3 = _mm_xor_si128(a3, b3);
    cost_sink ^= (uint64_t)_mm_cvtsi128_si64(_mm_xor_si128(_mm_xor_si128(a0,a1),_mm_xor_si128(a2,a3)));
}

int main(int argc, char **argv) {
    REQUIRE(argc == 3);
    const size_t n = (size_t)strtoul(argv[2], NULL, 10);
    REQUIRE(n >= 8 && n <= 4096);
    FILE *f = fopen(argv[1], "rb");
    REQUIRE(f != NULL && fseek(f, 0, SEEK_END) == 0);
    long length = ftell(f);
    REQUIRE(length > 0 && length % 130 == 0);
    size_t total = (size_t)length / 130;
    REQUIRE(total >= n);
    Record *records = allocate(n, sizeof(*records));
    unsigned char *expected = allocate(n, 1), *parsed = allocate(n, 1);
    S(pubkey) *keys = allocate(n, sizeof(*keys));
    S(ecdsa_signature) *sigs = allocate(n, sizeof(*sigs));
    Engine e = engine_create();
    for (size_t i = 0; i < n; ++i) {
        unsigned char raw[130];
        REQUIRE(fseek(f, (long)((i * total / n) * 130), SEEK_SET) == 0);
        REQUIRE(fread(raw, 1, 130, f) == 130);
        memcpy(records[i].msg, raw, 32);
        memcpy(records[i].sig, raw + 32, 64);
        memcpy(records[i].pub, raw + 96, 33);
        expected[i] = raw[129];
        REQUIRE(expected[i] <= 1);
        REQUIRE(ordinary(&e, &records[i]) == expected[i]);
        parsed[i] = (unsigned char)(S(ec_pubkey_parse)(e.ctx, &keys[i], records[i].pub, 33) &&
            S(ecdsa_signature_parse_compact)(e.ctx, &sigs[i], records[i].sig));
        if (parsed[i]) S(ecdsa_signature_normalize)(e.ctx, &sigs[i], &sigs[i]);
    }
    fclose(f);
    for (int mode = 0; mode < 2; ++mode) {
        memset(cost_counts, 0, sizeof(cost_counts));
        size_t passed = 0;
        cost_enabled = 1;
        for (size_t i = 0; i < n; ++i) {
            int ok = mode ? (parsed[i] && S(ecdsa_verify)(e.ctx, &sigs[i], records[i].msg, &keys[i])) : ordinary(&e, &records[i]);
            REQUIRE(ok == expected[i]);
            passed += (size_t)ok;
        }
        cost_enabled = 0;
        print_counts(mode ? "preparsed_verify" : "compressed_parse_and_verify", n, passed);
    }
#ifndef COST_INSTRUMENTED
    for (unsigned repeat = 0; repeat < 3; ++repeat) {
        for (int mode = 0; mode < 2; ++mode) {
            double cpu = seconds(CLOCK_THREAD_CPUTIME_ID), wall = seconds(CLOCK_MONOTONIC);
            for (size_t i = 0; i < n; ++i)
                cost_sink += (unsigned)(mode ? (parsed[i] && S(ecdsa_verify)(e.ctx, &sigs[i], records[i].msg, &keys[i])) : ordinary(&e, &records[i]));
            wall = seconds(CLOCK_MONOTONIC) - wall;
            cpu = seconds(CLOCK_THREAD_CPUTIME_ID) - cpu;
            printf("{\"timing\":\"%s\",\"repeat\":%u,\"operations\":%zu,\"cpu_seconds\":%.9f,\"wall_seconds\":%.9f}\n", mode ? "preparsed_verify" : "compressed_parse_and_verify", repeat, n, cpu, wall);
        }
        for (unsigned chains = 1; chains <= 4; chains *= 2) {
            const unsigned iterations = 100000;
            double cpu = seconds(CLOCK_THREAD_CPUTIME_ID), wall = seconds(CLOCK_MONOTONIC);
            sha_rounds(chains, iterations);
            wall = seconds(CLOCK_MONOTONIC) - wall;
            cpu = seconds(CLOCK_THREAD_CPUTIME_ID) - cpu;
            printf("{\"timing\":\"sha256rnds2_only\",\"chains\":%u,\"repeat\":%u,\"operations\":%llu,\"cpu_seconds\":%.9f,\"wall_seconds\":%.9f}\n", chains, repeat, (unsigned long long)iterations * 32 * chains, cpu, wall);
        }
    }
#endif
    engine_destroy(&e);
    free(records); free(expected); free(parsed); free(keys); free(sigs);
    return 0;
}

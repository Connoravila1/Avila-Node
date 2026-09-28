/* Feasibility probe: 4-lane AVX2 secp256k1 field mul (10x26 limb rep)
 * vs scalar fe_mul (5x52 __int128) from the vendored lib.
 * Differential-verified per-lane on random inputs.
 */
#define _POSIX_C_SOURCE 200809L
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "secp256k1.c"

#define S(name) rustsecp256k1_v0_10_0_##name

void S(default_illegal_callback_fn)(const char *str, void *data) {
    (void)str; (void)data; abort();
}
void S(default_error_callback_fn)(const char *str, void *data) {
    (void)str; (void)data; abort();
}

static double now_wall(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static const __m256i M26 = {0x3FFFFFFULL,0x3FFFFFFULL,0x3FFFFFFULL,0x3FFFFFFULL};
static const __m256i R0v = {0x3D10ULL,0x3D10ULL,0x3D10ULL,0x3D10ULL};
#define VADD _mm256_add_epi64
#define VMUL _mm256_mul_epu32   /* 32x32 -> 64 per lane; limbs <2^30 */
#define VSR  _mm256_srli_epi64
#define VSL  _mm256_slli_epi64
#define VAND _mm256_and_si256

/* a[10],b[10]: ymm j holds limb j of four field elems (canonical split =>
 * limbs <2^26). r[10] out. Products <2^52; p_k sums <= 10*2^52 < 2^56. */
static inline void fe_mul4(const __m256i a[10], const __m256i b[10],
                           __m256i r[10]) {
    __m256i p[19];
    for (int k = 0; k <= 18; k++) {
        __m256i acc = _mm256_setzero_si256();
        int lo = k < 9 ? 0 : k - 9, hi = k < 9 ? k : 9;
        for (int i = lo; i <= hi; i++)
            acc = VADD(acc, VMUL(a[i], b[k - i]));
        p[k] = acc;
    }
    /* fold limbs 10..18 into 0..9.
     * limb k>=10 at position p: contributes R0 to j=k-10, R1(<<10) to k-9.
     * Split each top limb into hi/lo (26b) first so R0*x stays <2^44. */
    for (int k = 10; k <= 18; k++) {
        __m256i lo = VAND(p[k], M26);
        __m256i hi = VSR(p[k], 26);
        /* lo sits at limb k:  -> R0*lo into limb k-10, R1*lo into k-9.
         * hi sits at limb k+1 -> R0*hi into limb k-9,  R1*hi into k-8. */
        p[k - 10] = VADD(p[k - 10], VMUL(R0v, lo));
        p[k - 9]  = VADD(p[k - 9],  VSL(lo, 10));
        p[k - 9]  = VADD(p[k - 9],  VMUL(R0v, hi));
        if (k - 8 <= 9)
            p[k - 8] = VADD(p[k - 8], VSL(hi, 10));
        else {
            /* k==18: hi*R1 sits at limb 10 -> refold x*2^260 =
             * x*R0 -> limb0, x*R1 -> limb1; split x again since
             * hi<<10 can exceed 26 bits */
            __m256i x = VSL(hi, 10);
            __m256i lo2 = VAND(x, M26), hi2 = VSR(x, 26);
            p[0] = VADD(p[0], VMUL(R0v, lo2));
            p[1] = VADD(p[1], VSL(lo2, 10));
            p[1] = VADD(p[1], VMUL(R0v, hi2));
            p[2] = VADD(p[2], VSL(hi2, 10));
        }
    }
    /* carry-normalize: 3 sweeps of limbs 0..8 + limb9 fold each pass */
    for (int pass = 0; pass < 3; pass++) {
        for (int j = 0; j < 9; j++) {
            __m256i c = VSR(p[j], 26);
            p[j] = VAND(p[j], M26);
            p[j + 1] = VADD(p[j + 1], c);
        }
        __m256i c = VSR(p[9], 26);
        p[9] = VAND(p[9], M26);
        p[0] = VADD(p[0], VMUL(R0v, c));
        p[1] = VADD(p[1], VSL(c, 10));
    }
    for (int j = 0; j < 10; j++) r[j] = p[j];
}

static void bytes_to_10x26(const unsigned char bbe[32], uint32_t o[10]) {
    /* fe_get_b32 is big-endian; field limbs are little-endian */
    unsigned char b[32];
    for (int i = 0; i < 32; i++) b[i] = bbe[31 - i];
    uint64_t w[4]; memcpy(w, b, 32);
    for (int i = 0; i < 10; i++) {
        int bit = i * 26, wl = bit >> 6, off = bit & 63;
        uint64_t v = w[wl] >> off;
        if (off > 38 && wl + 1 < 4) v |= w[wl + 1] << (64 - off);
        o[i] = (uint32_t)(v & 0x3FFFFFF);
    }
}
static void tenx26_to_bytes(const uint32_t l[10], unsigned char bbe[32]) {
    uint64_t w[4] = {0,0,0,0};
    for (int i = 0; i < 10; i++) {
        int bit = i * 26, wl = bit >> 6, off = bit & 63;
        uint64_t v = l[i];
        w[wl] |= v << off;
        if (off > 38 && wl + 1 < 4) w[wl + 1] |= v >> (64 - off);
    }
    for (int i = 0; i < 32; i++) bbe[i] = ((unsigned char *)w)[31 - i];
}

int main(void) {
    srand(42);
    /* ---------- correctness: 4-lane vs scalar on randoms ---------- */
    int fails = 0;
    for (int t = 0; t < 4000; t++) {
        __m256i va[10], vb[10], vr[10];
        unsigned char refb[4][32];
        uint32_t la[4][10], lb[4][10];
        for (int l = 0; l < 4; l++) {
            unsigned char ba[32], bb[32], ib[32];
            for (int i = 0; i < 32; i++) { ba[i] = rand(); bb[i] = rand(); }
            S(fe) fa, fb, fr;
            S(fe_set_b32_mod)(&fa, ba);
            S(fe_set_b32_mod)(&fb, bb);
            S(fe_mul)(&fr, &fa, &fb);
            S(fe_normalize)(&fr);
            S(fe_get_b32)(refb[l], &fr);
            S(fe_normalize)(&fa); S(fe_normalize)(&fb);
            S(fe_get_b32)(ib, &fa); bytes_to_10x26(ib, la[l]);
            S(fe_get_b32)(ib, &fb); bytes_to_10x26(ib, lb[l]);
        }
        for (int j = 0; j < 10; j++) {
            va[j] = _mm256_set_epi64x(la[3][j], la[2][j], la[1][j], la[0][j]);
            vb[j] = _mm256_set_epi64x(lb[3][j], lb[2][j], lb[1][j], lb[0][j]);
        }
        fe_mul4(va, vb, vr);
        uint64_t *q;
        for (int j = 0; j < 10; j++) {
            q = (uint64_t *)&vr[j];
            for (int l = 0; l < 4; l++) {
                /* lane limbs should be <2^26 normalized */
                if (q[l] >> 26) { fails++; }
            }
        }
        uint32_t out[4][10];
        for (int j = 0; j < 10; j++) {
            q = (uint64_t *)&vr[j];
            for (int l = 0; l < 4; l++) out[l][j] = (uint32_t)q[l];
        }
        for (int l = 0; l < 4; l++) {
            unsigned char got[32];
            tenx26_to_bytes(out[l], got);
            /* compare mod p: load both into fe and use fe_cmp */
            S(fe) fg, frf;
            S(fe_set_b32_mod)(&fg, got);
            S(fe_normalize)(&fg);
            /* reduce got mod p then byte-compare */
            unsigned char gb[32];
            S(fe_get_b32)(gb, &fg);
            S(fe_set_b32_mod)(&frf, refb[l]);
            S(fe_normalize)(&frf);
            unsigned char rb2[32];
            S(fe_get_b32)(rb2, &frf);
            if (memcmp(rb2, gb, 32)) { fails++; if (fails <= 2) {
                printf("MISMATCH t=%d lane %d\n  ref:", t, l);
                for (int i = 0; i < 32; i++) printf("%02x", rb2[i]);
                printf("\n  got:");
                for (int i = 0; i < 32; i++) printf("%02x", gb[i]);
                printf("\n  raw:");
                for (int i = 0; i < 32; i++) printf("%02x", got[i]);
                printf("\n");
            }}
        }
    }
    printf("correctness: %d fails / 16000 lanes\n", fails);

    /* ---------- throughput ---------- */
    int ITERS = 1000000;
    __m256i va[10], vb[10], vr[10];
    for (int j = 0; j < 10; j++) {
        va[j] = _mm256_set1_epi64x(0x2AAAAAA + j);
        vb[j] = _mm256_set1_epi64x(0x1555555 + j);
    }
    double t0 = now_wall();
    for (int i = 0; i < ITERS; i++) {
        fe_mul4(va, vb, vr);
        va[0] = VADD(va[0], VAND(vr[9], M26));
    }
    double t_4 = now_wall() - t0;

    S(fe) f1, f2, f3;
    memset(&f1, 0x11, sizeof(f1)); memset(&f2, 0x22, sizeof(f2));
    S(fe_normalize)(&f1); S(fe_normalize)(&f2);
    t0 = now_wall();
    for (int i = 0; i < ITERS; i++) {
        S(fe_mul)(&f3, &f1, &f2);
        memcpy(&f1, &f3, sizeof(f1));
    }
    double t_1 = now_wall() - t0;

    printf("4-lane fe_mul4: %.2f ns/group  = %.2f ns/mul\n",
           t_4 / ITERS * 1e9, t_4 / ITERS * 1e9 / 4);
    printf("scalar fe_mul : %.2f ns/mul\n", t_1 / ITERS * 1e9);
    printf("AVX2 speedup  : %.2fx per mul\n", t_1 / t_4 * 4);
    (void)f3;
    return 0;
}

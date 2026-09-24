/* MIT-licensed research harness, not linked into Avila Node.
 *
 * Test whether untrusted nonce-point advice allows efficient ECDSA batch
 * verification of unchanged signatures. Reuses the exact libsecp256k1 source
 * vendored by secp256k1-sys 0.10.1; private APIs are deliberately lab-only.
 * No new field/group arithmetic implementation, no unsafe Rust, no node changes.
 *
 * For each signature, reconstruct R with x(R) mod n = r, then check
 *    sum a_i * (s_i R_i - r_i Q_i - z_i G) = infinity.
 * Fresh nonzero scalar coefficients come from the verifier's getrandom AFTER
 * the complete immutable batch is available. Never use the all-ones control
 * outside the adversarial self-test. Batch failure falls back to ordinary
 * individual verification; a bad hint must not invalidate a valid signature.
 *
 * This measures an algebraic kernel, not Bitcoin Script, DER compatibility,
 * historical IBD, or production cryptographic assurance. See experiment report.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#include "secp256k1.c"

#define S(name) rustsecp256k1_v0_10_0_##name
#define MAX_BATCH 8192
#define SCRATCH_BYTES (16u << 20)
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "failed: %s at %s:%d\n", #x, __FILE__, __LINE__); exit(1); \
} } while (0)

typedef struct {
    unsigned char msg[32];
    unsigned char sig[64];
    unsigned char pub[33];
    unsigned char hint; /* bit 0: y parity; bit 1: x = r+n instead of r */
    unsigned char y[32]; /* only used by the larger-advice experiment */
} Record;

typedef struct {
    S(scalar) r, s, z, prefix, inverse;
    S(ge) q;
} InversionWork;

typedef struct {
    S(context) *ctx;
    void *context_memory;
    S(scratch) scratch;
    S(ge) *points;
    S(scalar) *scalars;
    unsigned char *random;
    InversionWork *inversion;
} Engine;

static double seconds(clockid_t clock) {
    struct timespec ts;
    REQUIRE(clock_gettime(clock, &ts) == 0);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void *allocate(size_t count, size_t size) {
    void *p = calloc(count, size);
    REQUIRE(p != NULL);
    return p;
}

static void entropy(unsigned char *out, size_t len) {
    while (len != 0) {
        ssize_t n = getrandom(out, len, 0);
        if (n < 0 && errno == EINTR) continue;
        REQUIRE(n > 0);
        out += (size_t)n;
        len -= (size_t)n;
    }
}

static Engine engine_create(void) {
    Engine e;
    memset(&e, 0, sizeof(e));
    e.context_memory = allocate(1, S(context_preallocated_size)(SECP256K1_CONTEXT_NONE));
    e.ctx = S(context_preallocated_create)(e.context_memory, SECP256K1_CONTEXT_NONE);
    REQUIRE(e.ctx != NULL);
    /* Rust's vendored dependency removes scratch malloc/free wrappers. Own
     * their documented struct storage here; ecmult restores its checkpoint. */
    memcpy(e.scratch.magic, "scratch", 8);
    e.scratch.data = allocate(1, SCRATCH_BYTES);
    e.scratch.max_size = SCRATCH_BYTES;
    e.points = allocate(2 * MAX_BATCH, sizeof(*e.points));
    e.scalars = allocate(2 * MAX_BATCH, sizeof(*e.scalars));
    e.random = allocate(MAX_BATCH, 32);
    e.inversion = allocate(MAX_BATCH, sizeof(*e.inversion));
    return e;
}

static void engine_destroy(Engine *e) {
    S(context_preallocated_destroy)(e->ctx);
    free(e->context_memory);
    free(e->scratch.data);
    free(e->points);
    free(e->scalars);
    free(e->random);
    free(e->inversion);
}

/* Matches the project's normalize-before-verifying mathematical convention.
 * DER/script encoding checks are outside BOTH timed paths in this harness. */
static int ordinary(Engine *e, const Record *r) {
    S(pubkey) pk;
    S(ecdsa_signature) sig;
    if (!S(ec_pubkey_parse)(e->ctx, &pk, r->pub, sizeof(r->pub)) ||
        !S(ecdsa_signature_parse_compact)(e->ctx, &sig, r->sig)) return 0;
    S(ecdsa_signature_normalize)(e->ctx, &sig, &sig);
    return S(ecdsa_verify)(e->ctx, &sig, r->msg, &pk);
}

static int parse(Engine *e, const Record *r, S(scalar) *rr, S(scalar) *ss,
                 S(scalar) *z, S(ge) *q) {
    S(pubkey) pk;
    S(ecdsa_signature) sig;
    if (!S(ec_pubkey_parse)(e->ctx, &pk, r->pub, sizeof(r->pub)) ||
        !S(ecdsa_signature_parse_compact)(e->ctx, &sig, r->sig)) return 0;
    S(ecdsa_signature_normalize)(e->ctx, &sig, &sig);
    S(ecdsa_signature_load)(e->ctx, rr, ss, &sig);
    if (S(scalar_is_zero)(rr) || S(scalar_is_zero)(ss)) return 0;
    S(scalar_set_b32)(z, r->msg, NULL);
    return S(pubkey_load)(e->ctx, q, &pk);
}

/* Ordinary ECDSA's point/x check using a supplied inverse. The x=r+n branch
 * mirrors ecdsa_impl.h (MIT, libsecp256k1 contributors). No probabilistic test
 * and no helper data: each resulting point is checked independently. */
static int verify_preinverted(const InversionWork *w) {
    S(scalar) u1, u2;
    S(gej) q, result;
    S(fe) x;
    unsigned char bytes[32];
    S(scalar_mul)(&u1, &w->inverse, &w->z);
    S(scalar_mul)(&u2, &w->inverse, &w->r);
    S(gej_set_ge)(&q, &w->q);
    S(ecmult)(&result, &q, &u2, &u1);
    if (S(gej_is_infinity)(&result)) return 0;
    S(scalar_get_b32)(bytes, &w->r);
    REQUIRE(S(fe_set_b32_limit)(&x, bytes));
    if (S(gej_eq_x_var)(&x, &result)) return 1;
    if (S(fe_cmp_var)(&x, &S(ecdsa_const_p_minus_order)) >= 0) return 0;
    S(fe_add)(&x, &S(ecdsa_const_order_as_fe));
    return S(gej_eq_x_var)(&x, &result);
}

/* Montgomery's trick: n inversions become one inverse and O(n) scalar
 * multiplications. Invalid inputs use a multiplicative placeholder of one,
 * never poison the other inverses, and remain false in the output mask. */
static void batch_inversion(Engine *e, const Record *records, size_t n,
                             unsigned char *valid) {
    S(scalar) product, inverse;
    size_t i;
    REQUIRE(n <= MAX_BATCH);
    if (n == 0) return;
    S(scalar_set_int)(&product, 1);
    for (i = 0; i < n; ++i) {
        InversionWork *w = &e->inversion[i];
        valid[i] = (unsigned char)parse(e, &records[i], &w->r, &w->s, &w->z, &w->q);
        if (!valid[i]) S(scalar_set_int)(&w->s, 1);
        w->prefix = product;
        S(scalar_mul)(&product, &product, &w->s);
    }
    S(scalar_inverse_var)(&inverse, &product);
    for (i = n; i-- > 0;) {
        InversionWork *w = &e->inversion[i];
        S(scalar_mul)(&w->inverse, &inverse, &w->prefix);
        S(scalar_mul)(&inverse, &inverse, &w->s);
    }
    for (i = 0; i < n; ++i) {
        if (valid[i]) valid[i] = (unsigned char)verify_preinverted(&e->inversion[i]);
    }
}

/* Create advice from public signature/message/key only. This repeats ordinary
 * curve multiplication and is separately timed, never hidden as free work. */
static int produce_hint(Engine *e, Record *record) {
    S(scalar) r, s, z, inverse, u1, u2, reduced_x;
    S(ge) q, nonce;
    S(gej) qj, result;
    unsigned char x[32];
    int carry;
    if (!parse(e, record, &r, &s, &z, &q)) return 0;
    S(scalar_inverse_var)(&inverse, &s);
    S(scalar_mul)(&u1, &inverse, &z);
    S(scalar_mul)(&u2, &inverse, &r);
    S(gej_set_ge)(&qj, &q);
    S(ecmult)(&result, &qj, &u2, &u1);
    if (S(gej_is_infinity)(&result)) return 0;
    S(ge_set_gej_var)(&nonce, &result);
    S(fe_normalize_var)(&nonce.x);
    S(fe_normalize_var)(&nonce.y);
    S(fe_get_b32)(x, &nonce.x);
    S(scalar_set_b32)(&reduced_x, x, &carry);
    if (!S(scalar_eq)(&reduced_x, &r)) return 0;
    record->hint = (unsigned char)(S(fe_is_odd)(&nonce.y) | (carry << 1));
    S(fe_get_b32)(record->y, &nonce.y);
    return 1;
}

static int nonce_from_hint(const Record *record, const S(scalar) *r,
                           S(ge) *nonce, int full_y) {
    unsigned char xbytes[32];
    S(fe) x, y;
    if (record->hint > 3) return 0;
    S(scalar_get_b32)(xbytes, r);
    if (!S(fe_set_b32_limit)(&x, xbytes)) return 0;
    if (record->hint & 2) {
        if (S(fe_cmp_var)(&x, &S(ecdsa_const_p_minus_order)) >= 0) return 0;
        S(fe_add)(&x, &S(ecdsa_const_order_as_fe));
    }
    S(fe_normalize_var)(&x);
    if (!full_y) return S(ge_set_xo_var)(nonce, &x, record->hint & 1);
    if (!S(fe_set_b32_limit)(&y, record->y) ||
        S(fe_is_odd)(&y) != (record->hint & 1)) return 0;
    S(ge_set_xy)(nonce, &x, &y);
    return S(ge_is_valid_var)(nonce);
}

static int term(S(scalar) *scalar, S(ge) *point, size_t index, void *opaque) {
    Engine *e = opaque;
    *scalar = e->scalars[index];
    *point = e->points[index];
    return 1;
}

/* 'ones' intentionally disables soundness for one cancellation-attack test.
 * Production integration is not provided. Normal probes always pass zero. */
static int batch(Engine *e, const Record *records, size_t n, int full_y, int ones) {
    S(scalar) generator;
    S(gej) result;
    size_t i;
    if (n > MAX_BATCH) return 0;
    if (n == 0) return 1;
    if (!ones) entropy(e->random, n * 32);
    S(scalar_set_int)(&generator, 0);
    for (i = 0; i < n; ++i) {
        S(scalar) r, s, z, a, contribution;
        S(ge) q, nonce;
        if (!parse(e, &records[i], &r, &s, &z, &q) ||
            !nonce_from_hint(&records[i], &r, &nonce, full_y)) return 0;
        if (ones) {
            S(scalar_set_int)(&a, 1);
        } else {
            int overflow;
            for (;;) {
                S(scalar_set_b32)(&a, e->random + 32*i, &overflow);
                if (!overflow && !S(scalar_is_zero)(&a)) break;
                entropy(e->random + 32*i, 32);
            }
        }
        e->points[2*i] = nonce;
        e->points[2*i+1] = q;
        S(scalar_mul)(&e->scalars[2*i], &a, &s);
        S(scalar_mul)(&e->scalars[2*i+1], &a, &r);
        S(scalar_negate)(&e->scalars[2*i+1], &e->scalars[2*i+1]);
        S(scalar_mul)(&contribution, &a, &z);
        S(scalar_add)(&generator, &generator, &contribution);
    }
    S(scalar_negate)(&generator, &generator);
    REQUIRE(S(ecmult_multi_var)(&e->ctx->error_callback, &e->scratch, &result,
                                &generator, term, e, 2*n));
    REQUIRE(e->scratch.alloc_size == 0);
    return S(gej_is_infinity)(&result);
}

static void with_fallback(Engine *e, const Record *r, size_t n, int full_y,
                          unsigned char *out) {
    size_t i;
    if (batch(e, r, n, full_y, 0)) {
        memset(out, 1, n);
    } else {
        for (i = 0; i < n; ++i) out[i] = (unsigned char)ordinary(e, &r[i]);
    }
}

static void deterministic_bytes(unsigned char out[32], uint64_t i, unsigned char domain) {
    S(sha256) h;
    unsigned char input[9];
    size_t j;
    input[0] = domain;
    for (j = 0; j < 8; ++j) input[j+1] = (unsigned char)(i >> (8*j));
    S(sha256_initialize)(&h);
    S(sha256_write)(&h, input, sizeof(input));
    S(sha256_finalize)(&h, out);
}

static void make_records(Engine *e, Record *records, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i) {
        unsigned char secret[32];
        S(pubkey) pk;
        S(ecdsa_signature) sig;
        size_t len = 33;
        deterministic_bytes(secret, (uint64_t)i, 1);
        deterministic_bytes(records[i].msg, (uint64_t)i, 2);
        REQUIRE(S(ec_pubkey_create)(e->ctx, &pk, secret));
        REQUIRE(S(ec_pubkey_serialize)(e->ctx, records[i].pub, &len, &pk, SECP256K1_EC_COMPRESSED));
        REQUIRE(len == 33);
        REQUIRE(S(ecdsa_sign)(e->ctx, &sig, records[i].msg, secret, NULL, NULL));
        REQUIRE(S(ecdsa_signature_serialize_compact)(e->ctx, records[i].sig, &sig));
        memset(secret, 0, sizeof(secret));
    }
}

/* Construct a valid x(R)=n+r case algebraically; finding it through random
 * signing would require an infeasible number of samples. No secret needed. */
static Record rare_carry(Engine *e) {
    Record record;
    S(scalar) r, s, z, inverse, negative;
    S(ge) nonce, q;
    S(gej) nj, qj;
    S(pubkey) pk;
    S(ecdsa_signature) sig;
    unsigned int i;
    size_t len = 33;
    memset(&record, 0, sizeof(record));
    record.hint = 2;
    for (i = 1; i < 1024; ++i) {
        S(scalar_set_int)(&r, i);
        if (nonce_from_hint(&record, &r, &nonce, 0)) break;
    }
    REQUIRE(i < 1024);
    S(scalar_set_int)(&s, 1);
    S(scalar_set_int)(&z, 1);
    S(scalar_inverse_var)(&inverse, &r);
    S(scalar_negate)(&negative, &inverse);
    S(gej_set_ge)(&nj, &nonce);
    S(ecmult)(&qj, &nj, &inverse, &negative); /* Q = r^-1 (R-G) */
    REQUIRE(!S(gej_is_infinity)(&qj));
    S(ge_set_gej_var)(&q, &qj);
    S(pubkey_save)(&pk, &q);
    REQUIRE(S(ec_pubkey_serialize)(e->ctx, record.pub, &len, &pk, SECP256K1_EC_COMPRESSED));
    S(ecdsa_signature_save)(&sig, &r, &s);
    REQUIRE(S(ecdsa_signature_serialize_compact)(e->ctx, record.sig, &sig));
    S(scalar_get_b32)(record.msg, &z);
    REQUIRE(produce_hint(e, &record));
    REQUIRE((record.hint & 2) != 0);
    REQUIRE(ordinary(e, &record));
    return record;
}

static void compare_fallback(Engine *e, const Record *records, size_t n) {
    unsigned char *bits = allocate(n, 1);
    size_t i;
    int mode;
    for (mode = 0; mode <= 1; ++mode) {
        with_fallback(e, records, n, mode, bits);
        for (i = 0; i < n; ++i) REQUIRE(bits[i] == ordinary(e, &records[i]));
    }
    batch_inversion(e, records, n, bits);
    for (i = 0; i < n; ++i) REQUIRE(bits[i] == ordinary(e, &records[i]));
    free(bits);
}

/* Plausible but incorrect advice: replace R by -R. Still on curve with the
 * correct x coordinate, so rejection requires the actual batch equation. */
static void flip_nonce(Record *record) {
    S(fe) y;
    REQUIRE(S(fe_set_b32_limit)(&y, record->y));
    S(fe_negate)(&y, &y, 1);
    S(fe_normalize_var)(&y);
    S(fe_get_b32)(record->y, &y);
    record->hint ^= 1;
}

static void selftest(Engine *e, const Record *valid) {
    Record test[8];
    Record pair[2];
    S(scalar) z, delta, neg, s;
    size_t i;
    int mode;
    const unsigned char order[32] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
    };
    REQUIRE(batch(e, valid, 0, 0, 0));
    for (mode = 0; mode <= 1; ++mode) REQUIRE(batch(e, valid, 8, mode, 0));
    memcpy(test, valid, sizeof(test));
    test[7] = rare_carry(e);
    for (mode = 0; mode <= 1; ++mode) REQUIRE(batch(e, test, 8, mode, 0));
    compare_fallback(e, test, 8);

    /* High-S normalization uses advice for the normalized, low-S signature. */
    S(scalar_set_b32)(&s, test[0].sig + 32, NULL);
    S(scalar_negate)(&s, &s);
    S(scalar_get_b32)(test[0].sig + 32, &s);
    REQUIRE(ordinary(e, &test[0]));
    for (mode = 0; mode <= 1; ++mode) REQUIRE(batch(e, test, 8, mode, 0));
    compare_fallback(e, test, 8);

    for (i = 0; i < 10; ++i) {
        memcpy(test, valid, sizeof(test));
        switch (i) {
            case 0: test[3].msg[0] ^= 1; break;
            case 1: memcpy(test[3].pub, valid[4].pub, 33); break;
            case 2: test[3].hint ^= 1; break;
            case 3: test[3].hint = 255; break;
            case 4: memset(test[3].sig, 0, 32); break;
            case 5: memset(test[3].sig + 32, 0, 32); break;
            case 6: memcpy(test[3].sig, order, 32); break;
            case 7: memcpy(test[3].sig + 32, order, 32); break;
            case 8: test[3].pub[0] = 0; break;
            case 9: test[3].hint ^= 2; break;
        }
        for (mode = 0; mode <= 1; ++mode) REQUIRE(!batch(e, test, 8, mode, 0));
        compare_fallback(e, test, 8);
    }
    memcpy(test, valid, sizeof(test));
    memset(test[3].y, 0, 32);
    REQUIRE(!batch(e, test, 8, 1, 0));
    compare_fallback(e, test, 8);
    memset(test[3].y, 255, 32);
    REQUIRE(!batch(e, test, 8, 1, 0));
    compare_fallback(e, test, 8);
    memcpy(test, valid, sizeof(test));
    flip_nonce(&test[3]);
    REQUIRE(ordinary(e, &test[3]));
    for (mode = 0; mode <= 1; ++mode) REQUIRE(!batch(e, test, 8, mode, 0));
    compare_fallback(e, test, 8);

    /* Two invalid signatures whose residuals cancel with equal weights. */
    pair[0] = pair[1] = valid[0];
    S(scalar_set_b32)(&z, valid[0].msg, NULL);
    S(scalar_set_int)(&delta, 1);
    S(scalar_negate)(&neg, &delta);
    S(scalar_add)(&s, &z, &delta);
    S(scalar_get_b32)(pair[0].msg, &s);
    S(scalar_add)(&s, &z, &neg);
    S(scalar_get_b32)(pair[1].msg, &s);
    REQUIRE(!ordinary(e, &pair[0]) && !ordinary(e, &pair[1]));
    for (mode = 0; mode <= 1; ++mode) {
        REQUIRE(batch(e, pair, 2, mode, 1)); /* demonstrates the attack */
        for (i = 0; i < 8; ++i) REQUIRE(!batch(e, pair, 2, mode, 0));
    }
    compare_fallback(e, pair, 2);
    {
        Record large[128];
        const size_t positions[] = {0, 1, 63, 64, 127};
        size_t k;
        for (i = 0; i < 128; ++i) large[i] = valid[i % 8];
        for (mode = 0; mode <= 1; ++mode) REQUIRE(batch(e, large, 128, mode, 0));
        for (k = 0; k < sizeof(positions)/sizeof(*positions); ++k) {
            size_t position = positions[k];
            large[position].msg[0] ^= 1;
            for (mode = 0; mode <= 1; ++mode) REQUIRE(!batch(e, large, 128, mode, 0));
            compare_fallback(e, large, 128);
            large[position].msg[0] ^= 1;
        }
    }
    printf("{\"mode\":\"selftest\",\"status\":\"pass\",\"cancellation_attack_demonstrated\":true,\"rare_x_ge_n\":true,\"fallback_masks_match\":true,\"batch_inverse_masks_match\":true}\n");
    fflush(stdout);
}

static void report(const char *mode, size_t count, size_t batch_size, size_t rep,
                    double wall, double cpu, size_t accepted) {
    printf("{\"mode\":\"%s\",\"count\":%zu,\"batch_size\":%zu,\"rep\":%zu,"
           "\"wall_seconds\":%.9f,\"cpu_seconds\":%.9f,\"us_per_sig\":%.6f,\"accepted\":%zu}\n",
           mode, count, batch_size, rep, wall, cpu, wall * 1e6 / (double)count, accepted);
    fflush(stdout);
}

int main(int argc, char **argv) {
    const size_t sizes[] = {8, 32, 128, 512, 2048, 8192};
    size_t count = 16384, repetitions = 3, i, rep, bs_index;
    Engine e;
    Record *records;
    double start, cpu;
    if (argc > 1) count = (size_t)strtoull(argv[1], NULL, 10);
    if (argc > 2) repetitions = (size_t)strtoull(argv[2], NULL, 10);
    REQUIRE(count >= 8 && count <= 1048576 && repetitions >= 1 && repetitions <= 100);
    e = engine_create();
    records = allocate(count, sizeof(*records));
    start = seconds(CLOCK_MONOTONIC);
    cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
    make_records(&e, records, count);
    report("generate_synthetic", count, 0, 0, seconds(CLOCK_MONOTONIC)-start,
           seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu, count);
    start = seconds(CLOCK_MONOTONIC);
    cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
    for (i = 0; i < count; ++i) REQUIRE(produce_hint(&e, &records[i]));
    report("produce_advice", count, 0, 0, seconds(CLOCK_MONOTONIC)-start,
           seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu, count);
    selftest(&e, records);
    if (getenv("ADVICE_SELFTEST_ONLY") == NULL) {
        for (rep = 0; rep < repetitions; ++rep) {
            size_t accepted = 0;
            start = seconds(CLOCK_MONOTONIC);
            cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
            for (i = 0; i < count; ++i) accepted += (size_t)ordinary(&e, &records[i]);
            REQUIRE(accepted == count);
            report("ordinary", count, 1, rep, seconds(CLOCK_MONOTONIC)-start,
                   seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu, accepted);
            for (bs_index = 0; bs_index < sizeof(sizes)/sizeof(*sizes); ++bs_index) {
                size_t bs = sizes[rep % 2 ? sizeof(sizes)/sizeof(*sizes)-1-bs_index : bs_index];
                int pass;
                unsigned char bits[MAX_BATCH];
                accepted = 0;
                start = seconds(CLOCK_MONOTONIC);
                cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
                for (i = 0; i < count; i += bs) {
                    size_t k, n = count-i < bs ? count-i : bs;
                    batch_inversion(&e, records+i, n, bits);
                    for (k = 0; k < n; ++k) accepted += bits[k];
                }
                REQUIRE(accepted == count);
                report("individual_batch_inverse", count, bs, rep,
                       seconds(CLOCK_MONOTONIC)-start, seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu, accepted);
                for (pass = 0; pass <= 1; ++pass) {
                    int mode = rep % 2 ? 1-pass : pass;
                    accepted = 0;
                    start = seconds(CLOCK_MONOTONIC);
                    cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
                    for (i = 0; i < count; i += bs) {
                        size_t n = count-i < bs ? count-i : bs;
                        REQUIRE(batch(&e, records+i, n, mode, 0));
                        accepted += n;
                    }
                    report(mode ? "batch_y33" : "batch_hint1", count, bs, rep,
                           seconds(CLOCK_MONOTONIC)-start, seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu, accepted);
                }
            }
            /* Charge failed batch work AND the ordinary fallback. One wrong,
             * on-curve nonce hint per batch; all underlying signatures valid. */
            for (i = 0; i < count; i += MAX_BATCH) flip_nonce(&records[i]);
            {
                int mode;
                unsigned char bits[MAX_BATCH];
                for (mode = 0; mode <= 1; ++mode) {
                    accepted = 0;
                    start = seconds(CLOCK_MONOTONIC);
                    cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
                    for (i = 0; i < count; i += MAX_BATCH) {
                        size_t k, n = count-i < MAX_BATCH ? count-i : MAX_BATCH;
                        with_fallback(&e, records+i, n, mode, bits);
                        for (k = 0; k < n; ++k) accepted += bits[k];
                    }
                    REQUIRE(accepted == count);
                    report(mode ? "bad_y33_fallback" : "bad_hint1_fallback", count,
                           MAX_BATCH, rep, seconds(CLOCK_MONOTONIC)-start,
                           seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu, accepted);
                }
            }
            for (i = 0; i < count; i += MAX_BATCH) flip_nonce(&records[i]);
        }
    }
    free(records);
    engine_destroy(&e);
    return 0;
}

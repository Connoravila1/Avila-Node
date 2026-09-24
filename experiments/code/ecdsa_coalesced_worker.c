/* MIT. Isolated experiment: combine repeated public-key terms in an ECDSA MSM.
 * The original kernel and production node sources remain unchanged.
 *
 * For every distinct canonical compressed key Q, replace its terms
 *   -a_1*r_1*Q - ... - a_k*r_k*Q
 * with one term -(sum a_i*r_i)*Q. Each signature retains its independently
 * sampled coefficient and its own nonce/message/signature checks. This is an
 * exact regrouping of the existing randomized equation, not a new soundness
 * argument for ECDSA batch verification.
 *
 * COALESCE_MODE: 0 = original; 1 = combine terms; 2 = also parse each key once.
 * Sorting bounds adversarial grouping cost to O(n log n), with a fixed 64 KiB
 * pointer array on this 64-bit host. Nothing is retained between batches.
 */
#define main original_kernel_main
#include "ecdsa_advice.c"
#undef main

#ifndef COALESCE_MODE
#define COALESCE_MODE 2
#endif
#if COALESCE_MODE < 0 || COALESCE_MODE > 2
#error Invalid COALESCE_MODE
#endif

static int key_order(const void *left, const void *right) {
    const Record *a = *(const Record *const *)left;
    const Record *b = *(const Record *const *)right;
    return memcmp(a->pub, b->pub, sizeof(a->pub));
}

/* Same signature/message checks as parse(), after an identical 33-byte key
 * has already been parsed successfully in this immutable batch. */
static int parse_signature(Engine *e, const Record *record, S(scalar) *r,
                           S(scalar) *s, S(scalar) *z) {
    S(ecdsa_signature) sig;
    if (!S(ecdsa_signature_parse_compact)(e->ctx, &sig, record->sig)) return 0;
    S(ecdsa_signature_normalize)(e->ctx, &sig, &sig);
    S(ecdsa_signature_load)(e->ctx, r, s, &sig);
    if (S(scalar_is_zero)(r) || S(scalar_is_zero)(s)) return 0;
    S(scalar_set_b32)(z, record->msg, NULL);
    return 1;
}

static int batch_coalesced(Engine *e, const Record *records, size_t n,
                           int full_y, int ones, int reuse_key) {
    const Record *ordered[MAX_BATCH];
    S(scalar) generator;
    S(gej) result;
    size_t i, unique = 0;
    if (n > MAX_BATCH) return 0;
    if (n == 0) return 1;
    /* The worker has already read every record before entering this function. */
    if (!ones) entropy(e->random, n * 32);
    for (i = 0; i < n; ++i) ordered[i] = records + i;
    qsort(ordered, n, sizeof(*ordered), key_order);
    S(scalar_set_int)(&generator, 0);
    for (i = 0; i < n; ++i) {
        const Record *record = ordered[i];
        size_t original_index = (size_t)(record - records);
        int new_key = i == 0 || memcmp(record->pub, ordered[i-1]->pub, 33) != 0;
        S(scalar) r, s, z, a, contribution;
        S(ge) q, nonce;
        if (!reuse_key || new_key) {
            if (!parse(e, record, &r, &s, &z, &q)) return 0;
        } else {
            if (!parse_signature(e, record, &r, &s, &z)) return 0;
            q = e->points[n + unique - 1];
        }
        if (!nonce_from_hint(record, &r, &nonce, full_y)) return 0;
        if (ones) {
            S(scalar_set_int)(&a, 1);
        } else {
            int overflow;
            for (;;) {
                S(scalar_set_b32)(&a, e->random + 32*original_index, &overflow);
                if (!overflow && !S(scalar_is_zero)(&a)) break;
                entropy(e->random + 32*original_index, 32);
            }
        }
        e->points[i] = nonce;
        S(scalar_mul)(&e->scalars[i], &a, &s);
        S(scalar_mul)(&contribution, &a, &r);
        S(scalar_negate)(&contribution, &contribution);
        if (new_key) {
            e->points[n + unique] = q;
            e->scalars[n + unique] = contribution;
            ++unique;
        } else {
            S(scalar_add)(&e->scalars[n + unique - 1],
                          &e->scalars[n + unique - 1], &contribution);
        }
        S(scalar_mul)(&contribution, &a, &z);
        S(scalar_add)(&generator, &generator, &contribution);
    }
    S(scalar_negate)(&generator, &generator);
    REQUIRE(S(ecmult_multi_var)(&e->ctx->error_callback, &e->scratch, &result,
                                &generator, term, e, n + unique));
    REQUIRE(e->scratch.alloc_size == 0);
    return S(gej_is_infinity)(&result);
}

static void make_shared_records(Engine *e, Record *records, size_t n, size_t keys,
                                int opposite_keys) {
    size_t i;
    for (i = 0; i < n; ++i) {
        unsigned char secret[32];
        S(pubkey) pk;
        S(ecdsa_signature) sig;
        size_t len = 33;
        deterministic_bytes(secret, (uint64_t)(i % keys), 71);
        if (opposite_keys && (i & 1)) REQUIRE(S(ec_seckey_negate)(e->ctx, secret));
        deterministic_bytes(records[i].msg, (uint64_t)i, 72);
        REQUIRE(S(ec_pubkey_create)(e->ctx, &pk, secret));
        REQUIRE(S(ec_pubkey_serialize)(e->ctx, records[i].pub, &len, &pk,
                                       SECP256K1_EC_COMPRESSED));
        REQUIRE(len == 33);
        REQUIRE(S(ecdsa_sign)(e->ctx, &sig, records[i].msg, secret, NULL, NULL));
        REQUIRE(S(ecdsa_signature_serialize_compact)(e->ctx, records[i].sig, &sig));
        memset(secret, 0, sizeof(secret));
        REQUIRE(produce_hint(e, &records[i]));
    }
}

static void assert_coalesced(Engine *e, const Record *records, size_t n, int want) {
    int full_y, reuse_key;
    for (full_y = 0; full_y < 2; ++full_y) {
        REQUIRE(batch(e, records, n, full_y, 0) == want);
        for (reuse_key = 0; reuse_key < 2; ++reuse_key)
            REQUIRE(batch_coalesced(e, records, n, full_y, 0, reuse_key) == want);
    }
}

static void coalesced_selftest(Engine *e) {
    const unsigned char order[32] = {
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,
        0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41
    };
    Record *records = allocate(MAX_BATCH, sizeof(*records));
    size_t i, k;
    int reuse_key, full_y;
    make_shared_records(e, records, 256, 256, 0);
    selftest(e, records); /* Retain the original independent arithmetic tests. */
    assert_coalesced(e, records, 0, 1);
    assert_coalesced(e, records, MAX_BATCH + 1, 0);
    assert_coalesced(e, records, 1, 1);
    assert_coalesced(e, records, 256, 1);
    for (k = 1; k <= 16; k *= 16) {
        make_shared_records(e, records, 256, k, 0);
        assert_coalesced(e, records, 256, 1);
        for (i = 0; i < 12; ++i) {
            Record saved = records[127];
            S(scalar) s;
            switch (i) {
                case 0: records[127].msg[0] ^= 1; break;
                case 1: flip_nonce(&records[127]); break;
                case 2: records[127].hint = 255; break;
                case 3: memset(records[127].sig, 0, 32); break;
                case 4: memset(records[127].sig + 32, 0, 32); break;
                case 5: memcpy(records[127].sig, order, 32); break;
                case 6: memcpy(records[127].sig + 32, order, 32); break;
                case 7: records[127].pub[0] = 0; break;
                case 8: records[127].pub[0] ^= 1; break;
                case 9: records[127].hint ^= 2; break;
                case 10: memset(records[127].pub + 1, 255, 32); break;
                case 11: /* Normalized high S must remain valid. */
                    S(scalar_set_b32)(&s, records[127].sig + 32, NULL);
                    S(scalar_negate)(&s, &s);
                    S(scalar_get_b32)(records[127].sig + 32, &s);
                    break;
            }
            assert_coalesced(e, records, 256, i == 11);
            records[127] = saved;
        }
    }
    /* Opposite compressed keys share x but must occupy distinct key groups. */
    make_shared_records(e, records, 256, 1, 1);
    REQUIRE(records[0].pub[0] != records[1].pub[0]);
    REQUIRE(memcmp(records[0].pub + 1, records[1].pub + 1, 32) == 0);
    assert_coalesced(e, records, 256, 1);
    records[255] = rare_carry(e);
    assert_coalesced(e, records, 256, 1);
    for (i = 256; i < MAX_BATCH; ++i) records[i] = records[i % 256];
    assert_coalesced(e, records, MAX_BATCH, 1);
    /* Invalid residuals with the SAME key cancel with all-one coefficients.
     * Coalescing must retain independent coefficients, including duplicates. */
    {
        Record pair[2] = {records[0], records[0]};
        S(scalar) z, delta, value;
        S(scalar_set_b32)(&z, records[0].msg, NULL);
        S(scalar_set_int)(&delta, 1);
        S(scalar_add)(&value, &z, &delta);
        S(scalar_get_b32)(pair[0].msg, &value);
        S(scalar_negate)(&delta, &delta);
        S(scalar_add)(&value, &z, &delta);
        S(scalar_get_b32)(pair[1].msg, &value);
        REQUIRE(!ordinary(e, pair) && !ordinary(e, pair + 1));
        for (reuse_key = 0; reuse_key < 2; ++reuse_key) {
            for (full_y = 0; full_y < 2; ++full_y) {
                REQUIRE(batch_coalesced(e, pair, 2, full_y, 1, reuse_key));
                for (i = 0; i < 8; ++i)
                    REQUIRE(!batch_coalesced(e, pair, 2, full_y, 0, reuse_key));
            }
        }
    }
    /* Modular addition may produce a zero aggregate public-key scalar. */
    for (i = 0; i < 256; ++i) {
        Record pair[2] = {records[i], records[i]};
        S(scalar) r;
        S(ge) nonce;
        S(scalar_set_b32)(&r, pair[1].sig, NULL);
        S(scalar_negate)(&r, &r);
        S(scalar_get_b32)(pair[1].sig, &r);
        pair[1].hint = 0;
        if (!nonce_from_hint(pair + 1, &r, &nonce, 0)) continue;
        for (reuse_key = 0; reuse_key < 2; ++reuse_key) {
            (void)batch_coalesced(e, pair, 2, 0, 1, reuse_key);
            REQUIRE(S(scalar_is_zero)(&e->scalars[2]));
        }
        break;
    }
    REQUIRE(i < 256);
    free(records);
    printf("{\"mode\":\"coalesced_selftest\",\"status\":\"pass\","
           "\"repeated_and_opposite_keys\":true,\"max_batch\":8192,"
           "\"same_key_cancellation\":true,\"zero_key_sum\":true}\n");
}

static void read_exact(void *out, size_t n) {
    REQUIRE(fread(out, 1, n, stdin) == n);
}

static void write_u64(uint64_t value) {
    unsigned char bytes[8];
    size_t i;
    for (i = 0; i < 8; ++i) bytes[i] = (unsigned char)(value >> (8*i));
    REQUIRE(fwrite(bytes, 1, 8, stdout) == 8);
}

int main(int argc, char **argv) {
    Engine e = engine_create();
    Record *records;
    unsigned char *answer;
    int cmd;
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        coalesced_selftest(&e);
        engine_destroy(&e);
        return 0;
    }
    /* Emit generated, valid public records only for the standalone benchmark. */
    if (argc == 4 && strcmp(argv[1], "--synthetic") == 0) {
        size_t n = (size_t)strtoull(argv[2], NULL, 10);
        size_t keys = (size_t)strtoull(argv[3], NULL, 10), i;
        REQUIRE(n > 0 && n <= MAX_BATCH && keys > 0 && keys <= n);
        records = allocate(n, sizeof(*records));
        make_shared_records(&e, records, n, keys, 0);
        for (i = 0; i < n; ++i) {
            REQUIRE(fwrite(records[i].msg, 1, 32, stdout) == 32);
            REQUIRE(fwrite(records[i].sig, 1, 64, stdout) == 64);
            REQUIRE(fwrite(records[i].pub, 1, 33, stdout) == 33);
            REQUIRE(fwrite(&records[i].hint, 1, 1, stdout) == 1);
        }
        free(records);
        engine_destroy(&e);
        return 0;
    }
    REQUIRE(argc == 1);
    records = allocate(MAX_BATCH, sizeof(*records));
    answer = allocate(MAX_BATCH, 1);
    while ((cmd = fgetc(stdin)) != EOF) {
        unsigned char size[4];
        uint32_t n;
        size_t i;
        double cpu = seconds(CLOCK_PROCESS_CPUTIME_ID);
        REQUIRE(cmd == 'P' || cmd == 'B' || cmd == 'V');
        read_exact(size, 4);
        n = (uint32_t)size[0] | (uint32_t)size[1] << 8 |
            (uint32_t)size[2] << 16 | (uint32_t)size[3] << 24;
        REQUIRE(n > 0 && n <= MAX_BATCH);
        for (i = 0; i < n; ++i) {
            read_exact(records[i].msg, 32);
            read_exact(records[i].sig, 64);
            read_exact(records[i].pub, 33);
            read_exact(&records[i].hint, 1);
        }
        if (cmd == 'B') {
            unsigned char accepted = (unsigned char)(COALESCE_MODE == 0 ?
                batch(&e, records, n, 0, 0) :
                batch_coalesced(&e, records, n, 0, 0, COALESCE_MODE == 2));
            REQUIRE(fwrite(&accepted, 1, 1, stdout) == 1);
        } else {
            for (i = 0; i < n; ++i)
                answer[i] = cmd == 'P' ?
                    (produce_hint(&e, &records[i]) ? records[i].hint : 255) :
                    (unsigned char)ordinary(&e, &records[i]);
            REQUIRE(fwrite(answer, 1, n, stdout) == n);
        }
        write_u64((uint64_t)((seconds(CLOCK_PROCESS_CPUTIME_ID) - cpu)*1e9));
        REQUIRE(fflush(stdout) == 0);
    }
    REQUIRE(!ferror(stdin));
    free(answer);
    free(records);
    engine_destroy(&e);
    return 0;
}

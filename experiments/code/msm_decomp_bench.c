/* MIT-licensed research harness, not linked into Avila Node.
 *
 * Phase decomposition of the advised-ECDSA batch (ecdsa_advice.c 'B' path):
 * the measured ~40us/sig bundles parse+lift+scalar+MSM. Price each stage
 * separately so the batch floor is modeled on measured pieces, not the
 * prototype's profile.
 *
 * Phases per batch of n valid records (hints produced once, untimed):
 *   A parse        — DER-ish compact parse + pubkey decompress + scalars
 *   B lift-y33     — nonce_from_hint with supplied affine y (no sqrt)
 *   B' lift-hint1  — nonce_from_hint hint-only (per-sig mod-p sqrt)
 *   C coeff prep   — a_i sampling + 4 scalar muls + 1 add per sig
 *   D MSM          — ecmult_multi_var on the 2n point/scalar array alone
 *   E batch()      — the composed path for reference
 *   F MSM scaling  — ecmult_multi_var at n terms in {256,1024,4096,16384}
 *   G ordinary     — individual verify baseline on a subset
 *   H pubkey parse — ec_pubkey_parse alone (the decompress+sqrt)
 *
 * Build (matches tools/ecdsa_parallel_bench.py):
 *   SECP=<cargo registry>/secp256k1-sys-0.10.1/depend/secp256k1
 *   cc -std=c99 -O3 -Wall -Wextra -Werror -Wno-unused-function \
 *      -Wno-unused-parameter -D_POSIX_C_SOURCE=200809L -include stdio.h \
 *      -DECMULT_WINDOW_SIZE=15 -DECMULT_GEN_PREC_BITS=4 \
 *      -I$SECP -I$SECP/src -I$SECP/include msm_decomp_bench.c \
 *      $SECP/src/precomputed_ecmult.c $SECP/src/precomputed_ecmult_gen.c \
 *      -o msm_decomp_bench
 * Run under tools/guard_run.sh --max 2048, pinned core.
 */
#define main synthetic_experiment_main
#include "ecdsa_advice.c"
#undef main

#define N 8192
#define REPS 7

static double cpu_now(void) { return seconds(CLOCK_PROCESS_CPUTIME_ID); }

static double median(double *v, size_t n) {
    size_t i, j;
    for (i = 0; i < n; ++i)
        for (j = i + 1; j < n; ++j)
            if (v[j] < v[i]) { double t = v[i]; v[i] = v[j]; v[j] = t; }
    return v[n / 2];
}

int main(void) {
    Engine e = engine_create();
    Record *records = allocate(N, sizeof(*records));
    S(scalar) *rs = allocate(N, sizeof(*rs));
    S(scalar) *ss_ = allocate(N, sizeof(*ss_));
    S(scalar) *zs = allocate(N, sizeof(*zs));
    S(ge) *qs = allocate(N, sizeof(*qs));
    S(ge) *nonces = allocate(N, sizeof(*nonces));
    double ts[REPS];
    size_t i;
    int r;
    double t0, acc;
    int sink = 0;

    fprintf(stderr, "generating %d records + hints (setup, untimed)...\n", N);
    make_records(&e, records, N);
    for (i = 0; i < N; ++i) REQUIRE(produce_hint(&e, &records[i]));

    /* ---- A: parse only ------------------------------------------------- */
    for (r = 0; r < REPS; ++r) {
        t0 = cpu_now(); acc = 0;
        for (i = 0; i < N; ++i)
            acc += parse(&e, &records[i], &rs[i], &ss_[i], &zs[i], &qs[i]);
        ts[r] = cpu_now() - t0; REQUIRE(acc == N);
    }
    printf("A parse           : %8.2f us/sig  (median of %d)\n",
           median(ts, REPS) * 1e6 / N, REPS);

    /* ---- A2: parse with advised pubkey-y (curve check, no sqrt) -------- */
    for (r = 0; r < REPS; ++r) {
        t0 = cpu_now(); acc = 0;
        for (i = 0; i < N; ++i)
            acc += parse_keyy(&e, &records[i], &rs[i], &ss_[i], &zs[i],
                              &qs[i]);
        ts[r] = cpu_now() - t0; REQUIRE(acc == N);
    }
    printf("A2 parse-keyy     : %8.2f us/sig  (y-hint + curve check)\n",
           median(ts, REPS) * 1e6 / N);

    /* ---- H2: key_from_hint alone --------------------------------------- */
    for (r = 0; r < REPS; ++r) {
        S(ge) q;
        t0 = cpu_now(); acc = 0;
        for (i = 0; i < N; ++i) acc += key_from_hint(&records[i], &q);
        ts[r] = cpu_now() - t0; REQUIRE(acc == N);
    }
    printf("H2 key_from_hint  : %8.2f us/sig\n", median(ts, REPS) * 1e6 / N);

    /* ---- B: lift, y33 (affine y supplied; curve check only) ------------ */
    for (r = 0; r < REPS; ++r) {
        t0 = cpu_now(); acc = 0;
        for (i = 0; i < N; ++i)
            acc += nonce_from_hint(&records[i], &rs[i], &nonces[i], 1);
        ts[r] = cpu_now() - t0; REQUIRE(acc == N);
    }
    printf("B lift-y33        : %8.2f us/sig\n", median(ts, REPS) * 1e6 / N);

    /* ---- B': lift, hint1 (mod-p sqrt per sig) --------------------------- */
    for (r = 0; r < REPS; ++r) {
        t0 = cpu_now(); acc = 0;
        for (i = 0; i < N; ++i)
            acc += nonce_from_hint(&records[i], &rs[i], &nonces[i], 0);
        ts[r] = cpu_now() - t0; REQUIRE(acc == N);
    }
    printf("B' lift-hint1     : %8.2f us/sig\n", median(ts, REPS) * 1e6 / N);

    /* ---- C: coefficient prep (scalars; arrays already hold points) ----- */
    entropy(e.random, N * 32); /* one bulk fill, untimed */
    for (r = 0; r < REPS; ++r) {
        S(scalar) generator;
        size_t j;
        t0 = cpu_now();
        S(scalar_set_int)(&generator, 0);
        for (j = 0; j < N; ++j) {
            S(scalar) a, contribution;
            int overflow;
            for (;;) {
                S(scalar_set_b32)(&a, e.random + 32 * j, &overflow);
                if (!overflow && !S(scalar_is_zero)(&a)) break;
                entropy(e.random + 32 * j, 32);
            }
            e.points[2 * j] = nonces[j];
            e.points[2 * j + 1] = qs[j];
            S(scalar_mul)(&e.scalars[2 * j], &a, &ss_[j]);
            S(scalar_mul)(&e.scalars[2 * j + 1], &a, &rs[j]);
            S(scalar_negate)(&e.scalars[2 * j + 1], &e.scalars[2 * j + 1]);
            S(scalar_mul)(&contribution, &a, &zs[j]);
            S(scalar_add)(&generator, &generator, &contribution);
        }
        sink += S(scalar_is_zero)(&generator);
        ts[r] = cpu_now() - t0;
    }
    printf("C coeff prep      : %8.2f us/sig  (excl. getrandom)\n",
           median(ts, REPS) * 1e6 / N);

    /* ---- D: MSM alone ---------------------------------------------------- */
    for (r = 0; r < REPS; ++r) {
        S(scalar) gen0; S(gej) result;
        t0 = cpu_now();
        S(scalar_set_int)(&gen0, 0);
        REQUIRE(S(ecmult_multi_var)(&e.ctx->error_callback, &e.scratch,
                                    &result, &gen0, term, &e, 2 * N));
        sink += S(gej_is_infinity)(&result);
        ts[r] = cpu_now() - t0;
    }
    printf("D MSM 2n terms    : %8.2f us/sig\n", median(ts, REPS) * 1e6 / N);

    /* ---- E: full batch() ------------------------------------------------- */
    for (r = 0; r < REPS; ++r) {
        t0 = cpu_now();
        REQUIRE(batch(&e, records, N, 1, 0));
        ts[r] = cpu_now() - t0;
    }
    printf("E batch() total   : %8.2f us/sig\n", median(ts, REPS) * 1e6 / N);

    /* ---- E2: batch_short — 96-bit R-side coefficients ------------------- */
    for (r = 0; r < REPS; ++r) {
        t0 = cpu_now();
        REQUIRE(batch_short(&e, records, N, 1));
        ts[r] = cpu_now() - t0;
    }
    printf("E2 batch_short    : %8.2f us/sig  (96-bit R coeffs)\n",
           median(ts, REPS) * 1e6 / N);
    /* tamper: corrupting one record's signature must fail the batch */
    {
        unsigned char saved = records[17].sig[0];
        int ok;
        records[17].sig[0] ^= 1;
        ok = batch_short(&e, records, N, 1);
        printf("E2 tamper check   : %s\n", ok == 0 ? "PASS (rejected)" : "FAIL");
        records[17].sig[0] = saved;
    }

    /* ---- E3: batch_short_keyy — short coeffs + advised key y ----------- */
    for (r = 0; r < REPS; ++r) {
        t0 = cpu_now();
        REQUIRE(batch_short_keyy(&e, records, N, 1));
        ts[r] = cpu_now() - t0;
    }
    printf("E3 batch_keyy     : %8.2f us/sig  (short coeff + key y-hint)\n",
           median(ts, REPS) * 1e6 / N);
    /* tamper 1: corrupt a key-y hint — must still verify (fallback path) */
    {
        unsigned char saved = records[17].qy[0];
        int ok;
        records[17].qy[0] ^= 1;
        ok = batch_short_keyy(&e, records, N, 1);
        printf("E3 bad keyy hint  : %s (fallback verified)\n",
               ok == 1 ? "PASS" : "FAIL");
        records[17].qy[0] = saved;
    }
    /* tamper 2: corrupt a signature — must reject */
    {
        unsigned char saved = records[17].sig[0];
        int ok;
        records[17].sig[0] ^= 1;
        ok = batch_short_keyy(&e, records, N, 1);
        printf("E3 sig tamper     : %s\n", ok == 0 ? "PASS (rejected)" : "FAIL");
        records[17].sig[0] = saved;
    }

    /* ---- E4: coalesced batch on dup-heavy records (~30% repeat keys) --- */
    {
        Record *drec = allocate(N, sizeof(*drec));
        size_t uq = 0;
        fprintf(stderr, "generating dup-heavy records (untimed)...\n");
        make_records_dup(&e, drec, N, 30);
        for (i = 0; i < N; ++i) REQUIRE(produce_hint(&e, &drec[i]));
        /* count unique pubkeys */
        {
            size_t j, k;
            for (j = 0; j < N; ++j) {
                int seen = 0;
                for (k = 0; k < j; ++k)
                    if (!memcmp(drec[j].pub, drec[k].pub, 33)) { seen = 1; break; }
                uq += !seen;
            }
        }
        fprintf(stderr, "unique pubkeys: %zu / %d (%.1f%% dup)\n",
                uq, N, 100.0 * (N - uq) / N);

        for (r = 0; r < REPS; ++r) {
            t0 = cpu_now();
            REQUIRE(batch_short_keyy(&e, drec, N, 1));
            ts[r] = cpu_now() - t0;
        }
        printf("E4a keyy on dup set    : %8.2f us/sig\n",
               median(ts, REPS) * 1e6 / N);

        for (r = 0; r < REPS; ++r) {
            t0 = cpu_now();
            REQUIRE(batch_short_keyy_coal(&e, drec, N, 1));
            ts[r] = cpu_now() - t0;
        }
        printf("E4b keyy+coalesce      : %8.2f us/sig  (n+g=%d+%zu terms)\n",
               median(ts, REPS) * 1e6 / N, N, uq);
        /* tamper: corrupt sig on dup set must reject */
        {
            unsigned char saved = drec[17].sig[0];
            int ok;
            drec[17].sig[0] ^= 1;
            ok = batch_short_keyy_coal(&e, drec, N, 1);
            printf("E4 tamper              : %s\n",
                   ok == 0 ? "PASS (rejected)" : "FAIL");
            drec[17].sig[0] = saved;
        }
        free(drec);
    }

    /* ---- P: producer cost, serial vs batched extraction ------------------ */
    {
        unsigned char *hy1 = allocate(N, 33), *hy2 = allocate(N, 33);
        size_t j;
        /* serial producer */
        for (r = 0; r < REPS; ++r) {
            t0 = cpu_now();
            for (j = 0; j < N; ++j) REQUIRE(produce_hint(&e, &records[j]));
            ts[r] = cpu_now() - t0;
        }
        for (j = 0; j < N; ++j) {
            hy1[j * 33] = records[j].hint;
            memcpy(hy1 + j * 33 + 1, records[j].y, 32);
        }
        printf("P1 produce serial      : %8.2f us/sig\n",
               median(ts, REPS) * 1e6 / N);
        /* batched producer on zeroed records — output must be identical */
        for (j = 0; j < N; ++j) {
            records[j].hint = 0;
            memset(records[j].y, 0, 32);
        }
        for (r = 0; r < REPS; ++r) {
            t0 = cpu_now();
            REQUIRE(produce_hints_batch(&e, records, N));
            ts[r] = cpu_now() - t0;
        }
        printf("P2 produce batched     : %8.2f us/sig\n",
               median(ts, REPS) * 1e6 / N);
        for (j = 0; j < N; ++j) {
            hy2[j * 33] = records[j].hint;
            memcpy(hy2 + j * 33 + 1, records[j].y, 32);
        }
        printf("P hints identical      : %s\n",
               !memcmp(hy1, hy2, N * 33) ? "PASS" : "FAIL");
        free(hy1);
        free(hy2);
    }

    /* ---- F: MSM marginal vs term count ---------------------------------- */
    {
        size_t k;
        for (k = 256; k <= 2 * N; k *= 4) {
            for (r = 0; r < 5; ++r) {
                S(scalar) gen0; S(gej) result;
                t0 = cpu_now();
                S(scalar_set_int)(&gen0, 0);
                REQUIRE(S(ecmult_multi_var)(&e.ctx->error_callback, &e.scratch,
                                            &result, &gen0, term, &e, k));
                sink += S(gej_is_infinity)(&result);
                ts[r] = cpu_now() - t0;
            }
            printf("F MSM %5zu terms : %8.2f us total, %7.2f us/term\n",
                   k, median(ts, 5) * 1e6, median(ts, 5) * 1e6 / k);
        }
    }

    /* ---- G: ordinary verify subset --------------------------------------- */
    {
        size_t m = 256;
        for (r = 0; r < 5; ++r) {
            t0 = cpu_now(); acc = 0;
            for (i = 0; i < m; ++i) acc += ordinary(&e, &records[i]);
            ts[r] = cpu_now() - t0; REQUIRE(acc == m);
        }
        printf("G ordinary        : %8.2f us/sig  (subset %zu)\n",
               median(ts, 5) * 1e6 / m, m);
    }

    /* ---- H: pubkey parse alone ------------------------------------------- */
    for (r = 0; r < 5; ++r) {
        S(pubkey) pk;
        t0 = cpu_now(); acc = 0;
        for (i = 0; i < N; ++i)
            acc += S(ec_pubkey_parse)(e.ctx, &pk, records[i].pub,
                                      sizeof(records[i].pub));
        ts[r] = cpu_now() - t0; REQUIRE(acc == N);
    }
    printf("H pubkey parse    : %8.2f us/sig\n", median(ts, 5) * 1e6 / N);

    fprintf(stderr, "sink=%d\n", sink);
    engine_destroy(&e);
    free(records); free(rs); free(ss_); free(zs); free(qs); free(nonces);
    return 0;
}

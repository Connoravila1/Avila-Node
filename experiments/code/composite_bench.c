/* Composite bench (#8 stage B): run the advised+coalesced batch on
 * REAL corpus sigs — records.bin emitted by corpus_extract is
 * (z32 || r||s64 || pub33) per resolved legacy input. This measures
 * the sig plane on real data: real DER, real sighashes, real dup rate.
 *
 * Flow per chunk of MAX_BATCH: producer fills hint/y (batched,
 * untimed — producer economics measured separately) + qy (pubkey
 * decompress, untimed producer-side), then TIME batch_short_keyy_coal.
 */
#define main ecdsa_advice_main_unused
#include "ecdsa_advice.c"
#undef main

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(int argc, char **argv) {
    FILE *f;
    Engine e;
    Record *recs;
    unsigned char *raw;
    size_t n_rec, cap = 4 * 1024 * 1024, i, n;
    double t0, t_batch = 0.0;
    int bad = 0;

    if (argc < 2) {
        fprintf(stderr, "usage: composite_bench records.bin\n");
        return 2;
    }
    setbuf(stdout, NULL);
    e = engine_create();
    f = fopen(argv[1], "rb");
    REQUIRE(f != NULL);
    raw = allocate(cap, 129);
    recs = allocate(cap, sizeof(Record));
    n_rec = fread(raw, 129, cap, f);
    fclose(f);
    REQUIRE(n_rec > 0);
    fprintf(stderr, "loaded %zu real records\n", n_rec);

    for (i = 0; i < n_rec; ++i) {
        unsigned char *p = raw + i * 129;
        memcpy(recs[i].msg, p, 32);
        memcpy(recs[i].sig, p + 32, 64);
        memcpy(recs[i].pub, p + 96, 33);
        recs[i].hint = 0;
        memset(recs[i].y, 0, 32);
        memset(recs[i].qy, 0, 32);
    }

    /* unique-pubkey census on real data: FNV-1a 64b tag per pub, sort,
     * count distinct (collision odds ~n^2/2^64 — negligible). */
    {
        uint64_t *tags = allocate(n_rec, sizeof(uint64_t));
        size_t uniq = 0;
        for (i = 0; i < n_rec; ++i) {
            uint64_t h = 1469598103934665603ULL;
            int k;
            for (k = 0; k < 33; ++k) { h ^= recs[i].pub[k]; h *= 1099511628211ULL; }
            tags[i] = h;
        }
        qsort(tags, n_rec, sizeof(uint64_t), cmp_u64);
        for (i = 0; i < n_rec; ++i)
            if (i == 0 || tags[i] != tags[i - 1]) ++uniq;
        fprintf(stderr, "unique pubs: %zu / %zu (%.1f%% dup)\n",
                uniq, n_rec, 100.0 * (n_rec - uniq) / n_rec);
        free(tags);
    }

    /* producer fills (untimed) + timed verifier batches, chunked */
    for (n = 0; n + MAX_BATCH <= n_rec; n += MAX_BATCH) {
        size_t j;
        Record *chunk = recs + n;
        /* producer side (untimed): hint+y via Montgomery batch, qy via
         * pubkey decompress */
        REQUIRE(produce_hints_batch(&e, chunk, MAX_BATCH));
        for (j = 0; j < MAX_BATCH; ++j) {
            S(scalar) r_, s_, z_;
            S(ge) q;
            S(fe) y;
            if (parse(&e, &chunk[j], &r_, &s_, &z_, &q)) {
                y = q.y;
                S(fe_normalize_var)(&y);
                S(fe_get_b32)(chunk[j].qy, &y);
            }
        }
        /* timed verifier */
        t0 = seconds(CLOCK_PROCESS_CPUTIME_ID);
        if (!batch_short_keyy_coal(&e, chunk, MAX_BATCH, 1)) bad++;
        t_batch += seconds(CLOCK_PROCESS_CPUTIME_ID) - t0;
    }
    fprintf(stderr, "advised+coalesced batch on real sigs: %.2f us/sig over %zu sigs (chunks failed: %d)\n",
            t_batch * 1e6 / n, n, bad);
    /* tamper: corrupt one sig in a fresh chunk — must reject */
    {
        Record *chunk = recs;
        REQUIRE(produce_hints_batch(&e, chunk, MAX_BATCH));
        {
            size_t j;
            for (j = 0; j < MAX_BATCH; ++j) {
                S(scalar) r_, s_, z_;
                S(ge) q;
                S(fe) y;
                if (parse(&e, &chunk[j], &r_, &s_, &z_, &q)) {
                    y = q.y;
                    S(fe_normalize_var)(&y);
                    S(fe_get_b32)(chunk[j].qy, &y);
                }
            }
        }
        chunk[123].sig[10] ^= 1;
        fprintf(stderr, "tamper check: %s\n",
                batch_short_keyy_coal(&e, chunk, MAX_BATCH, 1) ? "FAIL (accepted)" : "PASS (rejected)");
    }
    return 0;
}

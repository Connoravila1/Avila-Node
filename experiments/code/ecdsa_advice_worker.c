/* MIT. Experimental local arithmetic worker; never network-facing.
 * Preserve the original measured kernel byte-for-byte by including it here. */
#define main synthetic_experiment_main
#include "ecdsa_advice.c"
#undef main

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
    Engine e;
    Record *r;
    unsigned char *answer;
    int cmd;
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0) {
        char *args[] = {argv[0], "256", "1", NULL};
        return synthetic_experiment_main(3, args);
    }
    e = engine_create();
    r = allocate(MAX_BATCH, sizeof(*r));
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
            read_exact(r[i].msg, 32);
            read_exact(r[i].sig, 64);
            read_exact(r[i].pub, 33);
            read_exact(&r[i].hint, 1);
        }
        if (cmd == 'B') {
            unsigned char accepted = (unsigned char)batch(&e, r, n, 0, 0);
            REQUIRE(fwrite(&accepted, 1, 1, stdout) == 1);
        } else {
            for (i = 0; i < n; ++i) {
                answer[i] = cmd == 'P' ?
                    (produce_hint(&e, &r[i]) ? r[i].hint : 255) :
                    (unsigned char)ordinary(&e, &r[i]);
            }
            REQUIRE(fwrite(answer, 1, n, stdout) == n);
        }
        write_u64((uint64_t)((seconds(CLOCK_PROCESS_CPUTIME_ID)-cpu)*1e9));
        REQUIRE(fflush(stdout) == 0);
    }
    REQUIRE(!ferror(stdin));
    free(answer);
    free(r);
    engine_destroy(&e);
    return 0;
}

/* Sub-mul op-schedule probe (#6, lottery ticket): is there headroom
 * below the ROB in fe_mul? Measure throughput of
 *   (a) a dependent chain   x = x*y            (latency-bound)
 *   (b) two independent streams interleaved  a=a*y; b=b*z
 *   (c) four independent streams
 * If (b)/(c) already approach the port floor, below-ROB codegen can't
 * buy anything — the mul's internal ILP already saturates ports.
 */
#define main ecdsa_advice_main_unused
#include "ecdsa_advice.c"
#undef main

int main(void) {
    S(fe) a, b, c, d, y, z;
    double t0, t1;
    int i, reps = 2000000;

    memset(&y, 0, sizeof(y));
    y.n[0] = 7;
    memset(&z, 0, sizeof(z));
    z.n[0] = 9;
    a = y; b = z; c = y; d = z;

    /* (a) dependent chain — pure latency */
    t0 = seconds(CLOCK_PROCESS_CPUTIME_ID);
    for (i = 0; i < reps; ++i) {
        S(fe_mul)(&a, &a, &y);
    }
    t1 = seconds(CLOCK_PROCESS_CPUTIME_ID);
    fprintf(stderr, "dependent fe_mul chain : %6.1f ns/mul\n",
            (t1 - t0) * 1e9 / reps);

    /* (b) two independent streams */
    t0 = seconds(CLOCK_PROCESS_CPUTIME_ID);
    for (i = 0; i < reps; ++i) {
        S(fe_mul)(&a, &a, &y);
        S(fe_mul)(&b, &b, &z);
    }
    t1 = seconds(CLOCK_PROCESS_CPUTIME_ID);
    fprintf(stderr, "2x independent streams : %6.1f ns/mul\n",
            (t1 - t0) * 1e9 / (2 * reps));

    /* (c) four independent streams */
    t0 = seconds(CLOCK_PROCESS_CPUTIME_ID);
    for (i = 0; i < reps; ++i) {
        S(fe_mul)(&a, &a, &y);
        S(fe_mul)(&b, &b, &z);
        S(fe_mul)(&c, &c, &y);
        S(fe_mul)(&d, &d, &z);
    }
    t1 = seconds(CLOCK_PROCESS_CPUTIME_ID);
    fprintf(stderr, "4x independent streams : %6.1f ns/mul\n",
            (t1 - t0) * 1e9 / (4 * reps));

    /* sink */
    fprintf(stderr, "sink %lu %lu\n", a.n[0], b.n[0]);
    return 0;
}

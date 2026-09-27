/* Bounded instruction-timing probe: SHRD vs SHR+SHL+OR on the i3-N305
 * (Gracemont). Standalone. Measures throughput of 4 independent op-groups.
 *
 * Build: cc -O2 -o shrd_probe shrd_probe.c
 * Run:   taskset -c 7 nice -n 19 ./shrd_probe
 */
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

#define ITERS 40000000ull

/* low_word = (lo>>52)|(hi<<12) via SHRD (hi also shifted in real code; we
 * model the expensive part and keep values nonzero via acc feedback). */
static uint64_t shrd_grp(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    uint64_t acc = 0;
    for (uint64_t i = 0; i < ITERS; i++) {
        __asm__ volatile(
            "shrdq $52, %[b], %[a]\n\t"
            "shrdq $52, %[a], %[b]\n\t"
            "shrdq $52, %[d], %[c]\n\t"
            "shrdq $52, %[c], %[d]\n\t"
            : [a] "+r"(a), [b] "+r"(b), [c] "+r"(c), [d] "+r"(d));
        acc += a ^ b ^ c ^ d;
        a += acc; b += acc; c += acc; d += acc;
    }
    return acc;
}

/* Same cross-word extraction via shr+shl+or (3 cheap ops, no shrd). */
static uint64_t shs_grp(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
    uint64_t acc = 0;
    uint64_t t1 = a, t2 = b, t3 = c, t4 = d;
    for (uint64_t i = 0; i < ITERS; i++) {
        __asm__ volatile(
            "shrq $52, %[a]\n\tshlq $12, %[t1]\n\torq %[t1], %[a]\n\t"
            "shrq $52, %[b]\n\tshlq $12, %[t2]\n\torq %[t2], %[b]\n\t"
            "shrq $52, %[c]\n\tshlq $12, %[t3]\n\torq %[t3], %[c]\n\t"
            "shrq $52, %[d]\n\tshlq $12, %[t4]\n\torq %[t4], %[d]\n\t"
            : [a] "+r"(a), [b] "+r"(b), [c] "+r"(c), [d] "+r"(d),
              [t1] "+r"(t1), [t2] "+r"(t2), [t3] "+r"(t3), [t4] "+r"(t4)
            : );
        acc += a ^ b ^ c ^ d;
        a += acc; b += acc; c += acc; d += acc;
    }
    return acc;
}

int main(void) {
    uint64_t s = 0x9e3779b97f4a7c15ull;
    uint64_t a = s, b = s * 3, c = s * 5, d = s * 7;
    volatile uint64_t w = shrd_grp(a, b, c, d); (void)w;

    for (int rep = 0; rep < 3; rep++) {
        double t0 = now_ns();
        volatile uint64_t r1 = shrd_grp(a, b, c, d);
        double tt1 = now_ns();
        volatile uint64_t r2 = shs_grp(a, b, c, d);
        double tt2 = now_ns();
        printf("rep %d: shrd_x4 %8.1f ms (%5.2f ns/grp)  shs_x4 %8.1f ms (%5.2f ns/grp)  ratio %.2f\n",
               rep, (tt1 - t0) / 1e6, (tt1 - t0) / ITERS,
               (tt2 - tt1) / 1e6, (tt2 - tt1) / ITERS,
               (tt1 - t0) / (tt2 - tt1));
        (void)r1; (void)r2;
    }
    return 0;
}

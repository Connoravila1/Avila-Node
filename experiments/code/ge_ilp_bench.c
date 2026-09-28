/* Point-op ILP probe: 4 independent gej_double / gej_add_ge_var calls
 * back-to-back — do the field-op chains pipeline across calls? */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "secp256k1.c"
#define S(name) rustsecp256k1_v0_10_0_##name
void S(default_illegal_callback_fn)(const char *a, void *b){(void)a;(void)b;abort();}
void S(default_error_callback_fn)(const char *a, void *b){(void)a;(void)b;abort();}
static double now_wall(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+ts.tv_nsec*1e-9;}
int main(void) {
    S(ge) g; S(gej) j[4];
    memset(&g, 0x42, sizeof g);
    S(fe_normalize)(&g.x); S(fe_normalize)(&g.y);
    /* build a valid point via context: use generator multiples */
    void *mem = calloc(1, S(context_preallocated_size)(SECP256K1_CONTEXT_NONE));
    S(context) *ctx = S(context_preallocated_create)(mem, SECP256K1_CONTEXT_NONE);
    S(pubkey) pk; unsigned char sk[32]; memset(sk,1,32);
    S(ec_pubkey_create)(ctx, &pk, sk);
    S(fe) fx; S(ge_storage) gs;
    memcpy(&gs, &pk, sizeof gs); /* pubkey stores ge_storage internally */
    S(ge_from_storage)(&g, &gs);
    for (int i = 0; i < 4; i++) S(gej_set_ge)(&j[i], &g);
    int ITERS = 200000;
    /* serial dep baseline: single chain */
    double t0 = now_wall();
    for (int i = 0; i < ITERS; i++) {
        S(gej_double_var)(&j[0], &j[0], NULL);
        if (i % 256 == 255) S(gej_set_ge)(&j[0], &g);
    }
    printf("1x serial gej_double: %.1f ns/op\n", (now_wall()-t0)/ITERS*1e9);
    t0 = now_wall();
    for (int i = 0; i < ITERS; i++) {
        S(gej_add_ge_var)(&j[0], &j[0], &g, NULL);
        if (i % 256 == 255) S(gej_set_ge)(&j[0], &g);
    }
    printf("1x serial gej_add_ge: %.1f ns/op\n", (now_wall()-t0)/ITERS*1e9);
    t0 = now_wall();
    for (int i = 0; i < ITERS; i++) {
        S(gej_double_var)(&j[0], &j[0], NULL);
        S(gej_double_var)(&j[1], &j[1], NULL);
        S(gej_double_var)(&j[2], &j[2], NULL);
        S(gej_double_var)(&j[3], &j[3], NULL);
        /* restore-ish to avoid runaway: keep independent states, just track deps */
        if (i % 256 == 255) for (int k = 0; k < 4; k++) S(gej_set_ge)(&j[k], &g);
    }
    double t = now_wall() - t0;
    printf("4x indep gej_double : %.1f ns/op\n", t/ITERS/4*1e9);
    /* add: j[k] += g */
    t0 = now_wall();
    for (int i = 0; i < ITERS; i++) {
        S(gej_add_ge_var)(&j[0], &j[0], &g, NULL);
        S(gej_add_ge_var)(&j[1], &j[1], &g, NULL);
        S(gej_add_ge_var)(&j[2], &j[2], &g, NULL);
        S(gej_add_ge_var)(&j[3], &j[3], &g, NULL);
        if (i % 256 == 255) for (int k = 0; k < 4; k++) S(gej_set_ge)(&j[k], &g);
    }
    t = now_wall() - t0;
    printf("4x indep gej_add_ge : %.1f ns/op\n", t/ITERS/4*1e9);
    return 0;
}

/* Full-verify ILP probe: does calling ecdsa_verify on 4 INDEPENDENT sigs
 * back-to-back pipeline, vs dependent? */
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
    void *mem = calloc(1, S(context_preallocated_size)(SECP256K1_CONTEXT_NONE));
    S(context) *ctx = S(context_preallocated_create)(mem, SECP256K1_CONTEXT_NONE);
    unsigned char sk[4][32], pkser[4][64], msg[4][32], sigser[4][64];
    S(pubkey) pk[4]; S(ecdsa_signature) sig[4];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 32; j++) { sk[i][j] = 1+i+j; msg[i][j] = j*i+7; }
        S(ec_pubkey_create)(ctx, &pk[i], sk[i]);
        S(ecdsa_signature) s;
        S(ecdsa_sign)(ctx, &s, msg[i], sk[i], NULL, NULL);
        S(ecdsa_signature_serialize_compact)(ctx, sigser[i], &s);
        S(ecdsa_signature_parse_compact)(ctx, &sig[i], sigser[i]);
    }
    int ITERS = 20000, acc = 0;
    /* serial: verify sig0 4x (same data -> could cache internally? libsecp
     * doesn't cache; but same-input may branch-predict better) */
    double t0 = now_wall();
    for (int i = 0; i < ITERS; i++)
        for (int j = 0; j < 4; j++)
            acc += S(ecdsa_verify)(ctx, &sig[j], msg[j], &pk[j]);
    double t_all = now_wall() - t0;
    printf("4x indep verify : %.1f us/verify (acc=%d)\n", t_all/ITERS/4*1e6, acc);
    return 0;
}

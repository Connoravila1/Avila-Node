/* Merged-4 strauss ecmult — corrected: globalz before beta-mul; true
 * locals-form adds ported verbatim from gej_add_ge_var/gej_add_zinv_var. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "secp256k1.c"
#define S(n) rustsecp256k1_v0_10_0_##n
void S(default_illegal_callback_fn)(const char *a, void *b){(void)a;(void)b;abort();}
void S(default_error_callback_fn)(const char *a, void *b){(void)a;(void)b;abort();}
static double now_wall(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+ts.tv_nsec*1e-9;}

static inline void dbl(S(fe)*X,S(fe)*Y,S(fe)*Z,int*inf){
    S(fe) l,s,t;
    if (*inf) return;
    S(fe_mul)(Z, Z, Y);
    S(fe_sqr)(&s, Y); S(fe_sqr)(&l, X);
    S(fe_mul_int)(&l, 3); S(fe_half)(&l);
    S(fe_negate)(&t, &s, 1); S(fe_mul)(&t, &t, X);
    S(fe_sqr)(X, &l); S(fe_add)(X, &t); S(fe_add)(X, &t);
    S(fe_sqr)(&s, &s); S(fe_add)(&t, X);
    S(fe_mul)(Y, &t, &l); S(fe_add)(Y, &s); S(fe_negate)(Y, Y, 2);
}
static inline void add_ge(S(fe)*X,S(fe)*Y,S(fe)*Z,int*inf,const S(ge)*b){
    S(fe) z12,u2,s2,h,i,h2,h3,t;
    if (*inf) {
        if (b->infinity) { *inf=1; return; }
        *X=b->x; *Y=b->y; S(fe_set_int)(Z,1); *inf=0; return;
    }
    if (b->infinity) return;
    S(fe_sqr)(&z12, Z);
    S(fe_mul)(&u2, &b->x, &z12);
    S(fe_mul)(&s2, &b->y, &z12); S(fe_mul)(&s2, &s2, Z);
    S(fe_negate)(&h, X, 4); S(fe_add)(&h, &u2);
    S(fe_negate)(&i, &s2, 1); S(fe_add)(&i, Y);
    if (S(fe_normalizes_to_zero_var)(&h)) {
        if (S(fe_normalizes_to_zero_var)(&i)) dbl(X,Y,Z,inf);
        else *inf=1;
        return;
    }
    *inf=0;
    S(fe_mul)(Z, Z, &h);
    S(fe_sqr)(&h2, &h); S(fe_negate)(&h2, &h2, 1);
    S(fe_mul)(&h3, &h2, &h);
    S(fe_mul)(&t, X, &h2);
    S(fe_sqr)(X, &i); S(fe_add)(X, &h3); S(fe_add)(X, &t); S(fe_add)(X, &t);
    S(fe_add)(&t, X);
    S(fe_mul)(&h3, &h3, Y);          /* h3(-h^3)*s1 — before Y overwritten */
    S(fe_mul)(Y, &t, &i);
    S(fe_add)(Y, &h3);
}
static inline void add_zinv(S(fe)*X,S(fe)*Y,S(fe)*Z,int*inf,const S(ge)*b,const S(fe)*bz){
    S(fe) az,z12,u2,s2,h,i,h2,h3,t;
    if (*inf) {
        S(fe) bz2,bz3;
        *inf = b->infinity;
        S(fe_sqr)(&bz2, bz); S(fe_mul)(&bz3, &bz2, bz);
        S(fe_mul)(X, &b->x, &bz2); S(fe_mul)(Y, &b->y, &bz3);
        S(fe_set_int)(Z,1); return;
    }
    if (b->infinity) return;
    S(fe_mul)(&az, Z, bz);
    S(fe_sqr)(&z12, &az);
    S(fe_mul)(&u2, &b->x, &z12);
    S(fe_mul)(&s2, &b->y, &z12); S(fe_mul)(&s2, &s2, &az);
    S(fe_negate)(&h, X, 4); S(fe_add)(&h, &u2);
    S(fe_negate)(&i, &s2, 1); S(fe_add)(&i, Y);
    if (S(fe_normalizes_to_zero_var)(&h)) {
        if (S(fe_normalizes_to_zero_var)(&i)) dbl(X,Y,Z,inf);
        else *inf=1;
        return;
    }
    *inf=0;
    S(fe_mul)(Z, Z, &h);
    S(fe_sqr)(&h2, &h); S(fe_negate)(&h2, &h2, 1);
    S(fe_mul)(&h3, &h2, &h);
    S(fe_mul)(&t, X, &h2);
    S(fe_sqr)(X, &i); S(fe_add)(X, &h3); S(fe_add)(X, &t); S(fe_add)(X, &t);
    S(fe_add)(&t, X);
    S(fe_mul)(&h3, &h3, Y);
    S(fe_mul)(Y, &t, &i);
    S(fe_add)(Y, &h3);
}
#define TABLE_SIZE 8
typedef struct {
    S(fe) x,y,z; int inf;
    S(fe) Z;
    S(ge) pre_a[TABLE_SIZE];
    S(fe) aux[TABLE_SIZE];
    int wnaf_na_1[129], wnaf_na_lam[129], wnaf_ng_1[129], wnaf_ng_128[129];
    int bits_na_1, bits_na_lam, bits_ng_1, bits_ng_128;
} Lane;
static void lane_prep(Lane* L, const S(gej)*a, const S(scalar)*na, const S(scalar)*ng) {
    S(scalar) na1, nalam, ng1, ng128;
    S(gej) tmp = *a;
    S(fe_set_int)(&L->Z, 1);
    S(scalar_split_lambda)(&na1, &nalam, na);
    L->bits_na_1   = S(ecmult_wnaf)(L->wnaf_na_1,   129, &na1,   5);
    L->bits_na_lam = S(ecmult_wnaf)(L->wnaf_na_lam, 129, &nalam, 5);
    S(ecmult_odd_multiples_table)(TABLE_SIZE, L->pre_a, L->aux, &L->Z, &tmp);
    S(scalar_split_128)(&ng1, &ng128, ng);
    L->bits_ng_1   = S(ecmult_wnaf)(L->wnaf_ng_1,   129, &ng1,   15);
    L->bits_ng_128 = S(ecmult_wnaf)(L->wnaf_ng_128, 129, &ng128, 15);
    L->inf = 1;
}
static void ladder4(Lane* L) {
    /* hot gej state in NAMED LOCALS — array memory breaks the interleave */
    S(fe) x0,y0,z0, x1,y1,z1, x2,y2,z2, x3,y3,z3;
    int i0=1,i1=1,i2=1,i3=1;
    int bits = 0;
    for (int k = 0; k < 4; k++) {
        int b = L[k].bits_na_1; if (L[k].bits_na_lam>b) b=L[k].bits_na_lam;
        if (L[k].bits_ng_1>b) b=L[k].bits_ng_1; if (L[k].bits_ng_128>b) b=L[k].bits_ng_128;
        if (b>bits) bits=b;
    }
    for (int i = bits-1; i >= 0; i--) {
        int n; S(ge) tmpa;
        dbl(&x0,&y0,&z0,&i0); dbl(&x1,&y1,&z1,&i1);
        dbl(&x2,&y2,&z2,&i2); dbl(&x3,&y3,&z3,&i3);
        /* lane 0 */
        if (i<L[0].bits_na_1 && (n=L[0].wnaf_na_1[i])) {
            S(ecmult_table_get_ge)(&tmpa, L[0].pre_a, n, 5); add_ge(&x0,&y0,&z0,&i0,&tmpa); }
        if (i<L[0].bits_na_lam && (n=L[0].wnaf_na_lam[i])) {
            S(ecmult_table_get_ge_lambda)(&tmpa, L[0].pre_a, L[0].aux, n, 5); add_ge(&x0,&y0,&z0,&i0,&tmpa); }
        if (i<L[0].bits_ng_1 && (n=L[0].wnaf_ng_1[i])) {
            S(ecmult_table_get_ge_storage)(&tmpa, S(pre_g), n, 15); add_zinv(&x0,&y0,&z0,&i0,&tmpa,&L[0].Z); }
        if (i<L[0].bits_ng_128 && (n=L[0].wnaf_ng_128[i])) {
            S(ecmult_table_get_ge_storage)(&tmpa, S(pre_g_128), n, 15); add_zinv(&x0,&y0,&z0,&i0,&tmpa,&L[0].Z); }
        /* lane 1 */
        if (i<L[1].bits_na_1 && (n=L[1].wnaf_na_1[i])) {
            S(ecmult_table_get_ge)(&tmpa, L[1].pre_a, n, 5); add_ge(&x1,&y1,&z1,&i1,&tmpa); }
        if (i<L[1].bits_na_lam && (n=L[1].wnaf_na_lam[i])) {
            S(ecmult_table_get_ge_lambda)(&tmpa, L[1].pre_a, L[1].aux, n, 5); add_ge(&x1,&y1,&z1,&i1,&tmpa); }
        if (i<L[1].bits_ng_1 && (n=L[1].wnaf_ng_1[i])) {
            S(ecmult_table_get_ge_storage)(&tmpa, S(pre_g), n, 15); add_zinv(&x1,&y1,&z1,&i1,&tmpa,&L[1].Z); }
        if (i<L[1].bits_ng_128 && (n=L[1].wnaf_ng_128[i])) {
            S(ecmult_table_get_ge_storage)(&tmpa, S(pre_g_128), n, 15); add_zinv(&x1,&y1,&z1,&i1,&tmpa,&L[1].Z); }
        /* lane 2 */
        if (i<L[2].bits_na_1 && (n=L[2].wnaf_na_1[i])) {
            S(ecmult_table_get_ge)(&tmpa, L[2].pre_a, n, 5); add_ge(&x2,&y2,&z2,&i2,&tmpa); }
        if (i<L[2].bits_na_lam && (n=L[2].wnaf_na_lam[i])) {
            S(ecmult_table_get_ge_lambda)(&tmpa, L[2].pre_a, L[2].aux, n, 5); add_ge(&x2,&y2,&z2,&i2,&tmpa); }
        if (i<L[2].bits_ng_1 && (n=L[2].wnaf_ng_1[i])) {
            S(ecmult_table_get_ge_storage)(&tmpa, S(pre_g), n, 15); add_zinv(&x2,&y2,&z2,&i2,&tmpa,&L[2].Z); }
        if (i<L[2].bits_ng_128 && (n=L[2].wnaf_ng_128[i])) {
            S(ecmult_table_get_ge_storage)(&tmpa, S(pre_g_128), n, 15); add_zinv(&x2,&y2,&z2,&i2,&tmpa,&L[2].Z); }
        /* lane 3 */
        if (i<L[3].bits_na_1 && (n=L[3].wnaf_na_1[i])) {
            S(ecmult_table_get_ge)(&tmpa, L[3].pre_a, n, 5); add_ge(&x3,&y3,&z3,&i3,&tmpa); }
        if (i<L[3].bits_na_lam && (n=L[3].wnaf_na_lam[i])) {
            S(ecmult_table_get_ge_lambda)(&tmpa, L[3].pre_a, L[3].aux, n, 5); add_ge(&x3,&y3,&z3,&i3,&tmpa); }
        if (i<L[3].bits_ng_1 && (n=L[3].wnaf_ng_1[i])) {
            S(ecmult_table_get_ge_storage)(&tmpa, S(pre_g), n, 15); add_zinv(&x3,&y3,&z3,&i3,&tmpa,&L[3].Z); }
        if (i<L[3].bits_ng_128 && (n=L[3].wnaf_ng_128[i])) {
            S(ecmult_table_get_ge_storage)(&tmpa, S(pre_g_128), n, 15); add_zinv(&x3,&y3,&z3,&i3,&tmpa,&L[3].Z); }
    }
    L[0].x=x0;L[0].y=y0;L[0].z=z0;L[0].inf=i0;
    L[1].x=x1;L[1].y=y1;L[1].z=z1;L[1].inf=i1;
    L[2].x=x2;L[2].y=y2;L[2].z=z2;L[2].inf=i2;
    L[3].x=x3;L[3].y=y3;L[3].z=z3;L[3].inf=i3;
    for (int k = 0; k < 4; k++)
        if (!L[k].inf) S(fe_mul)(&L[k].z, &L[k].z, &L[k].Z);
}
int main(void){
    void *mem = calloc(1, S(context_preallocated_size)(SECP256K1_CONTEXT_NONE));
    S(context) *ctx = S(context_preallocated_create)(mem, SECP256K1_CONTEXT_NONE);
    srand(7);
    S(gej) a[4]; S(scalar) na[4], ng[4];
    for (int k = 0; k < 4; k++) {
        unsigned char sk[32]; for (int i=0;i<32;i++) sk[i]=rand();
        S(pubkey) pk; S(ec_pubkey_create)(ctx,&pk,sk);
        S(ge_storage) gs; memcpy(&gs,&pk,sizeof gs);
        S(ge) g; S(ge_from_storage)(&g,&gs); S(gej_set_ge)(&a[k],&g);
        unsigned char s32[32]; for (int i=0;i<32;i++) s32[i]=rand();
        S(scalar_set_b32)(&na[k], s32, NULL);
        for (int i=0;i<32;i++) s32[i]=rand();
        S(scalar_set_b32)(&ng[k], s32, NULL);
    }
    S(gej) rref[4];
    for (int k = 0; k < 4; k++) S(ecmult)(&rref[k], &a[k], &na[k], &ng[k]);
    Lane L[4];
    for (int k = 0; k < 4; k++) {
        lane_prep(&L[k], &a[k], &na[k], &ng[k]);
        S(ge_table_set_globalz)(TABLE_SIZE, L[k].pre_a, L[k].aux);
        for (int i = 0; i < TABLE_SIZE; i++)
            S(fe_mul)(&L[k].aux[i], &L[k].pre_a[i].x, &S(const_beta));
    }
    ladder4(L);
    int ok=1;
    for (int k = 0; k < 4; k++) {
        S(ge) ga,gb;
        { S(gej) t; t.x=L[k].x;t.y=L[k].y;t.z=L[k].z;t.infinity=L[k].inf;
          S(ge_set_gej_var)(&ga,&t); }
        S(ge_set_gej_var)(&gb,&rref[k]);
        unsigned char ba[32],bb[32],ya[32],yb[32];
        S(fe_normalize)(&ga.x); S(fe_normalize)(&gb.x);
        S(fe_get_b32)(ba,&ga.x); S(fe_get_b32)(bb,&gb.x);
        S(fe_normalize)(&ga.y); S(fe_normalize)(&gb.y);
        S(fe_get_b32)(ya,&ga.y); S(fe_get_b32)(yb,&gb.y);
        if (memcmp(ba,bb,32)||memcmp(ya,yb,32)) { ok=0; printf("lane %d mismatch\n",k); }
    }
    printf("correct: %d\n", ok);
    int ITERS=2000;
    double t0; unsigned long acc=0;
    t0=now_wall();
    for (int it=0; it<ITERS; it++)
        for (int k = 0; k < 4; k++) { S(ecmult)(&rref[k], &a[k], &na[k], &ng[k]); na[k].d[0] += (it&1); acc+=rref[k].x.n[0]; }
    double tseq=now_wall()-t0;
    t0=now_wall();
    for (int it=0; it<ITERS; it++) {
        ladder4(L);
        for (int k = 0; k < 4; k++) { acc += L[k].x.n[0]; L[k].pre_a[0].x.n[0] += (it&1); }
    }
    double tm4=now_wall()-t0;
    printf("acc %lu\n", acc);
    /* dbl-only comparison inside same binary */
    { S(fe) d0x,d0y,d0z,d1x,d1y,d1z,d2x,d2y,d2z,d3x,d3y,d3z; int e0=1,e1=1,e2=1,e3=1;
      memset(&d0x,0x11,sizeof d0x); memset(&d0y,0x22,sizeof d0y); memset(&d0z,0x01,sizeof d0z);
      S(fe_normalize)(&d0x);S(fe_normalize)(&d0y);S(fe_normalize)(&d0z);
      d1x=d0x;d1y=d0y;d1z=d0z;d2x=d0x;d2y=d0y;d2z=d0z;d3x=d0x;d3y=d0y;d3z=d0z;
      t0=now_wall();
      for (int it=0; it<ITERS*10; it++) {
        for (int i = 0; i < 129; i++) {
            dbl(&d0x,&d0y,&d0z,&e0); dbl(&d1x,&d1y,&d1z,&e1);
            dbl(&d2x,&d2y,&d2z,&e2); dbl(&d3x,&d3y,&d3z,&e3);
        }
        e0=e1=e2=e3=1; d0x.n[0] += it;
      }
      double dd=now_wall()-t0;
      volatile uint64_t snk = d0x.n[0]+d3z.n[4]; (void)snk;
      printf("merged-4 dbl-only : %.1f ns/dbl\n",dd/(ITERS*10)/129/4*1e9); }
    printf("4x scalar ecmult : %.1f us/ecmult\n", tseq/ITERS/4*1e6);
    printf("merged-4 ecmult  : %.1f us/ecmult (%.2fx)\n", tm4/ITERS/4*1e6, tseq/tm4);
    return 0;
}

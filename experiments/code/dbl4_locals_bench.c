/* gej_double formula on NAMED LOCAL fe vars — no pointer/struct access. */
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

/* straight-line double on local fe's: X,Y,Z -> X',Y',Z' */
static inline void dbl(S(fe)*X,S(fe)*Y,S(fe)*Z){
    S(fe) l,s,t;
    S(fe_mul)(Z, Z, Y);          /* Z' = Y*Z */
    S(fe_sqr)(&s, Y);            /* s = Y^2 */
    S(fe_sqr)(&l, X);            /* l = X^2 */
    S(fe_mul_int)(&l, 3); S(fe_half)(&l);
    S(fe_negate)(&t, &s, 1);
    S(fe_mul)(&t, &t, X);        /* t = -X*s */
    S(fe_sqr)(X, &l);            /* X' = l^2 */
    S(fe_add)(X, &t); S(fe_add)(X, &t);
    S(fe_sqr)(&s, &s);           /* s' = s^2 */
    S(fe_add)(&t, X);
    S(fe_mul)(Y, &t, &l);        /* Y' = l*(X'+t) */
    S(fe_add)(Y, &s); S(fe_negate)(Y, Y, 2);
}
int main(void){
    /* 4 lanes of locals */
    S(fe) X0,Y0,Z0,X1,Y1,Z1,X2,Y2,Z2,X3,Y3,Z3;
    memset(&X0,0x11,sizeof X0);memset(&Y0,0x22,sizeof Y0);memset(&Z0,0x01,sizeof Z0);
    X1=X0;Y1=Y0;Z1=Z0;X2=X0;Y2=Y0;Z2=Z0;X3=X0;Y3=Y0;Z3=Z0;
    S(fe_normalize)(&X0);S(fe_normalize)(&Y0);S(fe_normalize)(&Z0);
    int ITERS=300000;
    double t0=now_wall();
    for(int i=0;i<ITERS;i++){
        dbl(&X0,&Y0,&Z0); dbl(&X1,&Y1,&Z1); dbl(&X2,&Y2,&Z2); dbl(&X3,&Y3,&Z3);
        if(i%200==199){X0=(S(fe)){{{0x11,0x22,0x33,0x44,0}}};Y0=X0;Z0=X0;
                       X1=X0;Y1=X0;Z1=X0;X2=X0;Y2=X0;Z2=X0;X3=X0;Y3=X0;Z3=X0;}
    }
    double tt=now_wall()-t0;
    printf("4x local-fe dbl  : %.1f ns/op\n",tt/ITERS/4*1e9);
    /* serial 1-lane for baseline */
    t0=now_wall();
    for(int i=0;i<ITERS*4;i++){ dbl(&X0,&Y0,&Z0); if(i%200==199){X0=(S(fe)){{{0x11,0x22,0x33,0x44,0}}};Y0=X0;Z0=X0;} }
    printf("1x local-fe dbl  : %.1f ns/op\n",(now_wall()-t0)/ITERS/4*1e9);
    return 0;
}

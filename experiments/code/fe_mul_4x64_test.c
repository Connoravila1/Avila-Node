#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
typedef unsigned __int128 u128;
#include "secp256k1.c"
#define S(n) rustsecp256k1_v0_10_0_##n
void S(default_illegal_callback_fn)(const char *a, void *b){(void)a;(void)b;abort();}
void S(default_error_callback_fn)(const char *a, void *b){(void)a;(void)b;abort();}
extern void fe_mul_4x64_asm(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
static double now_wall(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+ts.tv_nsec*1e-9;}
static const uint64_t P[4]={0xFFFFFFFEFFFFFC2FULL,~0ULL,~0ULL,~0ULL};
static int ge_p(const uint64_t r[4]){for(int i=3;i>=0;i--){if(r[i]!=P[i])return r[i]>P[i];}return 1;}
static void pack5(S(fe)*f, const uint64_t a[4]) {
    unsigned char b[32];
    for (int i=0;i<4;i++) for(int j=0;j<8;j++) b[(3-i)*8+7-j]=(a[i]>>(j*8))&0xff;
    S(fe_set_b32_mod)(f, b);
}
static uint64_t rnd(void){return ((uint64_t)rand()<<32)|((uint64_t)rand()<<1);}
int main(void){
    srand(12345);
    int ok=1;
    for(int t=0;t<10000;t++){
        uint64_t a[4]={rnd(),rnd(),rnd(),rnd()&0x7fffffffffffffffULL};
        uint64_t b[4]={rnd(),rnd(),rnd(),rnd()&0x7fffffffffffffffULL};
        if (ge_p(a)){u128 s;/*make <p*/ a[0]-=0xFFFFFC2FULL; }
        if (ge_p(b)){ b[0]-=0xFFFFFC2FULL; }
        uint64_t r[4]; fe_mul_4x64_asm(r,a,b);
        /* canonical subtract if >= p */
        if (ge_p(r)){unsigned __int128 s;uint64_t rr[4];
            s=(u128)r[0]-P[0];rr[0]=s; s=(u128)r[1]-P[1]-(s>>127);rr[1]=s;
            s=(u128)r[2]-P[2]-(s>>127);rr[2]=s; s=(u128)r[3]-P[3]-(s>>127);rr[3]=s;
            memcpy(r,rr,32);}
        S(fe) fa,fb,fr; pack5(&fa,a);pack5(&fb,b);S(fe_mul)(&fr,&fa,&fb);
        unsigned char want[32];S(fe_normalize)(&fr);S(fe_get_b32)(want,&fr);
        unsigned char got[32];
        for (int i=0;i<4;i++) for(int j=0;j<8;j++) got[(3-i)*8+7-j]=(r[i]>>(j*8))&0xff;
        if (memcmp(want,got,32)){ok=0;if(t<5){printf("mismatch t=%d\n",t);}}
    }
    printf("correct: %d (10000 cases)\n",ok);
    /* timing: serial chain x=x*b */
    uint64_t a[4]={0x1234567890abcdefULL,0xfedcba0987654321ULL,0x0badc0ffee0df00dULL,0x0123456789abcdeULL};
    uint64_t b[4]={0xdeadbeefcafebabeULL,0x1122334455667788ULL,0x99aabbccddeeff00ULL,0x01020304050607ULL};
    int ITERS=4000000;uint64_t x[4];memcpy(x,a,32);
    double t0=now_wall();
    for(int i=0;i<ITERS;i++)fe_mul_4x64_asm(x,x,b);
    printf("asm 4x64 serial : %.1f ns/mul\n",(now_wall()-t0)/ITERS*1e9);
    uint64_t x1[4],x2[4],x3[4],x4[4];
    memcpy(x1,a,32);memcpy(x2,b,32);
    memcpy(x3,a,32);x3[0]^=1;memcpy(x4,b,32);x4[0]^=1;
    t0=now_wall();
    for(int i=0;i<ITERS/4;i++){
        fe_mul_4x64_asm(x1,x1,b);fe_mul_4x64_asm(x2,x2,b);
        fe_mul_4x64_asm(x3,x3,b);fe_mul_4x64_asm(x4,x4,b);
    }
    printf("asm 4x64 indep4 : %.1f ns/mul\n",(now_wall()-t0)/(ITERS/4)/4*1e9);
    volatile uint64_t sink=x1[0]+x2[0]+x3[0]+x4[0]+x[0];(void)sink;
    return 0;
}

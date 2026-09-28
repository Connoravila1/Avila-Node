#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "secp256k1.c"
#define S(n) rustsecp256k1_v0_10_0_##n
void S(default_illegal_callback_fn)(const char *a, void *b){(void)a;(void)b;}
void S(default_error_callback_fn)(const char *a, void *b){(void)a;(void)b;}
extern void fe_mul4x64_batch4(uint64_t*, const uint64_t*, const uint64_t*);
extern void fe_mul_4x64_asm(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]);
extern void fe_mul4x64_chain(uint64_t r[4], uint64_t a[4], const uint64_t b[4], uint64_t iters);
static double now_wall(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return ts.tv_sec+ts.tv_nsec*1e-9;}
static void pack5(S(fe)*f, const uint64_t a[4]) {
    unsigned char b[32];
    for (int i=0;i<4;i++) for(int j=0;j<8;j++) b[(3-i)*8+7-j]=(a[i]>>(j*8))&0xff;
    S(fe_set_b32_mod)(f, b);
}
int main(void){
    uint64_t a[4]={0x1234567890abcdefULL,0xfedcba0987654321ULL,0x0badc0ffee0df00dULL,0x0123456789abcdeULL};
    uint64_t b[4]={0xdeadbeefcafebabeULL,0x1122334455667788ULL,0x99aabbccddeeff00ULL,0x01020304050607ULL};
    S(fe) fa,fb; pack5(&fa,a); pack5(&fb,b);
    int ITERS=4000000;
    S(fe) x=fa; double t0=now_wall();
    for(int i=0;i<ITERS;i++) S(fe_mul)(&x,&x,&fb);
    printf("5x52 serial   : %.1f ns/mul\n",(now_wall()-t0)/ITERS*1e9);
    uint64_t xbuf[4]; memcpy(xbuf,a,32);
    t0=now_wall();
    fe_mul4x64_chain(xbuf, xbuf, b, ITERS);
    printf("asm chain     : %.1f ns/mul (incl ~1ns feedback)\n",(now_wall()-t0)/ITERS*1e9);
    memcpy(xbuf,a,32);
    t0=now_wall();
    for(int i=0;i<ITERS;i++) fe_mul_4x64_asm(xbuf,xbuf,b);
    printf("asm 1/call    : %.1f ns/mul\n",(now_wall()-t0)/ITERS*1e9);
    S(fe) x1=fa,x2=fb,x3=fa,x4=fb;
    x3.n[0]^=1; x4.n[0]^=1;
    t0=now_wall();
    for(int i=0;i<ITERS/4;i++){
        S(fe_mul)(&x1,&x1,&fb);S(fe_mul)(&x2,&x2,&fb);
        S(fe_mul)(&x3,&x3,&fb);S(fe_mul)(&x4,&x4,&fb);
    }
    printf("5x52 indep4   : %.1f ns/mul\n",(now_wall()-t0)/(ITERS/4)/4*1e9);
    /* batch4: 4 indep muls per call */
    uint64_t aa[16],bb[16],rr[16];
    for(int i=0;i<16;i++){aa[i]=a[i&3]+i;bb[i]=b[i&3]+i;}
    t0=now_wall();
    for(int i=0;i<ITERS/4;i++) fe_mul4x64_batch4(rr,aa,bb);
    printf("asm batch4    : %.1f ns/mul\n",(now_wall()-t0)/(ITERS/4)/4*1e9);
    volatile uint64_t sink2=rr[0]+rr[15];(void)sink2;
    volatile uint64_t sink=xbuf[0]+x.n[0]+x1.n[0]+x2.n[0]+x3.n[0]+x4.n[0];(void)sink;
    return 0;
}
extern void fe_mul4x64_batch4(uint64_t*, const uint64_t*, const uint64_t*);
